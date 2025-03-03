from flask import Flask, render_template, request, redirect, url_for, flash, make_response, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
import io
from xhtml2pdf import pisa
import secrets
import os
import pyotp, qrcode
import io
from flask import send_file

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///delovni_nalog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'test_key'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'prijava'


class Podjetje(db.Model):
    __tablename__ = 'Podjetja'
    idPodjetja = db.Column(db.Integer, primary_key=True)
    nazivPodjetja = db.Column(db.String(100), nullable=False)
    kljucPodjetja = db.Column(db.String(64), unique=True, nullable=False)

    logo_filename = db.Column(db.String(200), nullable=True)

    uporabniki = db.relationship('Uporabnik', backref='podjetje', lazy=True)

class Uporabnik(UserMixin, db.Model):
    __tablename__ = 'Uporabniki'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='user')  
    company_id = db.Column(db.Integer, db.ForeignKey('Podjetja.idPodjetja'), nullable=True)
    approved = db.Column(db.Boolean, default=False)


    company_id = db.Column(db.Integer, db.ForeignKey('Podjetja.idPodjetja'), nullable=True)
    otp_secret = db.Column(db.String(32), nullable=True)
    two_factor_enabled = db.Column(db.Boolean, default=False)

    def set_password(self, geslo):
        self.password_hash = generate_password_hash(geslo)

    def check_password(self, geslo):
        return check_password_hash(self.password_hash, geslo)

@login_manager.user_loader
def load_user(user_id):
    return Uporabnik.query.get(int(user_id))


class SeznamProjektov(db.Model):
    __tablename__ = 'SeznamProjektov'
    idProjekta = db.Column(db.Integer, primary_key=True)
    naziv_projekta = db.Column(db.String(45), nullable=False)
    narocnik = db.Column(db.String(45), nullable=True)


    company_id = db.Column(db.Integer, db.ForeignKey('Podjetja.idPodjetja'), nullable=True)

    glave_nalogov = db.relationship("GlavaDelovnegaNaloga", backref="projekt", lazy=True)

class GlavaDelovnegaNaloga(db.Model):
    __tablename__ = 'GlavaDelovnegaNaloga'
    idGlava_delovnega_naloga = db.Column(db.Integer, primary_key=True)
    naslovDN = db.Column(db.String(45), nullable=False)
    status = db.Column(db.String(20), default='V pripravi')

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey('Uporabniki.id'))
    updated_by_id = db.Column(db.Integer, db.ForeignKey('Uporabniki.id'))

    created_by = db.relationship("Uporabnik", foreign_keys=[created_by_id])
    updated_by = db.relationship("Uporabnik", foreign_keys=[updated_by_id])

    seznam_projektov_idProjekta = db.Column(db.Integer, db.ForeignKey('SeznamProjektov.idProjekta'), nullable=False)


    company_id = db.Column(db.Integer, db.ForeignKey('Podjetja.idPodjetja'), nullable=True)

    postavke = db.relationship("PostavkeDelovnegaNaloga", backref="glava_naloga", lazy=True)

class SeznamIdentov(db.Model):
    __tablename__ = 'SeznamIdentov'
    id = db.Column(db.Integer, primary_key=True)
    naziv = db.Column(db.String(45), nullable=False)
    merska_enota = db.Column(db.String(45), nullable=True)


    company_id = db.Column(db.Integer, db.ForeignKey('Podjetja.idPodjetja'), nullable=True)

    postavke = db.relationship("PostavkeDelovnegaNaloga", backref="ident", lazy=True)

class PostavkeDelovnegaNaloga(db.Model):
    __tablename__ = 'PostavkeDelovnegaNaloga'
    idPostavke = db.Column(db.Integer, primary_key=True)
    glava_delovnega_naloga_id = db.Column(db.Integer, db.ForeignKey('GlavaDelovnegaNaloga.idGlava_delovnega_naloga'), nullable=False)
    seznam_identov_id = db.Column(db.Integer, db.ForeignKey('SeznamIdentov.id'), nullable=False)
    kolicina = db.Column(db.Integer, default=1)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey('Uporabniki.id'))
    updated_by_id = db.Column(db.Integer, db.ForeignKey('Uporabniki.id'))

    created_by = db.relationship("Uporabnik", foreign_keys=[created_by_id])
    updated_by = db.relationship("Uporabnik", foreign_keys=[updated_by_id])


    company_id = db.Column(db.Integer, db.ForeignKey('Podjetja.idPodjetja'), nullable=True)

STATUSI = ["V pripravi", "V teku", "Zaključeno", "Preklicano"]


@app.route('/registracija', methods=['GET', 'POST'])
def registracija():
    if current_user.is_authenticated:
        return redirect(url_for('seznam_delovnih_nalogov'))

    if request.method == 'POST':
        uporabnisko_ime = request.form.get('username')
        geslo = request.form.get('password')
        kljuc_podjetja = request.form.get('company_key')

        if not uporabnisko_ime or not geslo or not kljuc_podjetja:
            flash('Vnesi uporabniško ime, geslo in ključ podjetja.', 'error')
            return redirect(url_for('registracija'))


        podjetje = Podjetje.query.filter_by(kljucPodjetja=kljuc_podjetja).first()
        if not podjetje:
            flash('Neveljaven ključ podjetja.', 'error')
            return redirect(url_for('registracija'))

        obstojeci = Uporabnik.query.filter_by(username=uporabnisko_ime).first()
        if obstojeci:
            flash('Uporabniško ime že obstaja. Izberi drugo.', 'error')
            return redirect(url_for('registracija'))


        nov = Uporabnik(
            username=uporabnisko_ime,
            role='user',
            company_id=podjetje.idPodjetja,
            approved=False
        )
        nov.set_password(geslo)

        db.session.add(nov)
        db.session.commit()

        flash('Registracija uspešna! Prijavite se zdaj.')
        return redirect(url_for('prijava'))

    return render_template('registracija.html')

@app.route('/prijava', methods=['GET', 'POST'])
def prijava():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        uporabnisko_ime = request.form.get('username')
        geslo = request.form.get('password')

        user = Uporabnik.query.filter_by(username=uporabnisko_ime).first()
        if user and user.check_password(geslo):
 
            if not user.approved:
                flash('Vaš račun še ni odobren.')
                return redirect(url_for('prijava'))

         
            if user.two_factor_enabled:
                session['2fa_user_id'] = user.id
                flash('Vnesite 2FA kodo.')
                return redirect(url_for('verify_2fa'))
            else:
          
                login_user(user)
                flash('Prijava uspešna.')
                return redirect(url_for('index'))
        else:
            flash('Nepravilno uporabniško ime ali geslo.')
            return redirect(url_for('prijava'))

    return render_template('prijava.html')

@app.route('/odjava')
def odjava():
    logout_user()
    flash('Uspešno odjavljen.')
    return redirect(url_for('prijava'))




@app.route('/')
@login_required
def index():

    glave = GlavaDelovnegaNaloga.query.filter_by(company_id=current_user.company_id).all()
    return render_template('domov.html', glave=glave)

@app.route('/seznam_delovnih_nalogov')
@login_required
def seznam_delovnih_nalogov():
    glave = GlavaDelovnegaNaloga.query.filter_by(company_id=current_user.company_id).all()
    return render_template('seznam_delovnih_nalogov.html', glave=glave)

@app.route('/podrobnosti_delovnega_naloga/<int:id_glave>')
@login_required
def podrobnosti_delovnega_naloga(id_glave):

    glava = GlavaDelovnegaNaloga.query.filter_by(
        idGlava_delovnega_naloga=id_glave,
        company_id=current_user.company_id
    ).first_or_404()
    return render_template('podrobnosti_delovnega_naloga.html', glava=glava)

@app.route('/dodaj_delovni_nalog', methods=['GET', 'POST'])
@login_required
def dodaj_delovni_nalog():

    projekti = SeznamProjektov.query.filter_by(company_id=current_user.company_id).all()
    if request.method == 'POST':
        naslovDN = request.form.get('naslovDN')
        projekt_id = request.form.get('projekt_id')

  
        nova_glava = GlavaDelovnegaNaloga(
            naslovDN=naslovDN,
            seznam_projektov_idProjekta=projekt_id,
            created_by_id=current_user.id,
            updated_by_id=current_user.id,
            company_id=current_user.company_id
        )
        db.session.add(nova_glava)
        db.session.commit()
        return redirect(url_for('seznam_delovnih_nalogov'))
    return render_template('dodaj_delovni_nalog.html', projekti=projekti)

@app.route('/dodaj_postavko/<int:id_glave>', methods=['GET', 'POST'])
@login_required
def dodaj_postavko(id_glave):

    glava = GlavaDelovnegaNaloga.query.filter_by(
        idGlava_delovnega_naloga=id_glave,
        company_id=current_user.company_id
    ).first_or_404()

    identi = SeznamIdentov.query.filter_by(company_id=current_user.company_id).all()
    if request.method == 'POST':
        ident_id = request.form.get('ident_id')
        kolicina = request.form.get('kolicina') or 1

        nova_postavka = PostavkeDelovnegaNaloga(
            glava_delovnega_naloga_id=glava.idGlava_delovnega_naloga,
            seznam_identov_id=ident_id,
            kolicina=kolicina,
            created_by_id=current_user.id,
            updated_by_id=current_user.id,
            company_id=current_user.company_id
        )
        db.session.add(nova_postavka)
        db.session.commit()
        return redirect(url_for('podrobnosti_delovnega_naloga', id_glave=glava.idGlava_delovnega_naloga))

    return render_template('dodaj_postavko.html', glava=glava, identi=identi)

@app.route('/uredi_status/<int:id_glave>', methods=['GET', 'POST'])
@login_required
def uredi_status(id_glave):
    glava = GlavaDelovnegaNaloga.query.filter_by(
        idGlava_delovnega_naloga=id_glave,
        company_id=current_user.company_id
    ).first_or_404()
    if request.method == 'POST':
        nov_status = request.form.get('status')
        glava.status = nov_status
        glava.updated_by_id = current_user.id
        db.session.commit()
        return redirect(url_for('podrobnosti_delovnega_naloga', id_glave=glava.idGlava_delovnega_naloga))
    return render_template('uredi_status.html', glava=glava, statusi=["V pripravi", "V teku", "Zaključeno", "Preklicano"])


@app.route('/izvoz_pdf/<int:id_glave>')
@login_required
def izvoz_pdf(id_glave):

    glava = GlavaDelovnegaNaloga.query.filter_by(
        idGlava_delovnega_naloga=id_glave,
        company_id=current_user.company_id
    ).first_or_404()

    html_content = render_template('pdf_template.html', glava=glava)

    pdf_file = io.BytesIO()
    pisa.CreatePDF(io.StringIO(html_content), dest=pdf_file)
    pdf_file.seek(0)

    response = make_response(pdf_file.read())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'inline; filename=DelovniNalog_{id_glave}.pdf'
    return response



@app.route('/seznam_identov')
@login_required
def seznam_identov():

    identi = SeznamIdentov.query.filter_by(company_id=current_user.company_id).all()
    return render_template('seznam_identov.html', identi=identi)

@app.route('/dodaj_ident', methods=['GET', 'POST'])
@login_required
def dodaj_ident():
    if request.method == 'POST':
        naziv = request.form.get('naziv')
        merska_enota = request.form.get('merska_enota')
        
        if not naziv:
            flash('Naziv identa je obvezen.', 'error')
            return redirect(url_for('dodaj_ident'))

        nov_ident = SeznamIdentov(
            naziv=naziv,
            merska_enota=merska_enota,
            company_id=current_user.company_id
        )
        db.session.add(nov_ident)
        db.session.commit()
        flash(f'Ident "{naziv}" uspešno dodan.')
        return redirect(url_for('seznam_identov'))

    return render_template('dodaj_ident.html')

@app.route('/uredi_ident/<int:id_ident>', methods=['GET', 'POST'])
@login_required
def uredi_ident(id_ident):
    ident = SeznamIdentov.query.filter_by(
        id=id_ident,
        company_id=current_user.company_id
    ).first_or_404()

    if request.method == 'POST':
        novi_naziv = request.form.get('naziv')
        nova_merska = request.form.get('merska_enota')

        if not novi_naziv:
            flash('Naziv identa je obvezen.', 'error')
            return redirect(url_for('uredi_ident', id_ident=id_ident))

        ident.naziv = novi_naziv
        ident.merska_enota = nova_merska
        db.session.commit()
        flash('Ident uspešno posodobljen.')
        return redirect(url_for('seznam_identov'))

    return render_template('uredi_ident.html', ident=ident)

@app.route('/izbrisi_ident/<int:id_ident>', methods=['POST'])
@login_required
def izbrisi_ident(id_ident):
    ident = SeznamIdentov.query.filter_by(
        id=id_ident,
        company_id=current_user.company_id
    ).first_or_404()

    db.session.delete(ident)
    db.session.commit()
    flash('Ident izbrisan.')
    return redirect(url_for('seznam_identov'))



@app.route('/seznam_projektov')
@login_required
def seznam_projektov():
    projekti = SeznamProjektov.query.filter_by(company_id=current_user.company_id).all()
    return render_template('seznam_projektov.html', projekti=projekti)

@app.route('/dodaj_projekt', methods=['GET', 'POST'])
@login_required
def dodaj_projekt():
    if request.method == 'POST':
        naziv_projekta = request.form.get('naziv_projekta')
        narocnik = request.form.get('narocnik')

        if not naziv_projekta:
            flash('Naziv projekta je obvezen.', 'error')
            return redirect(url_for('dodaj_projekt'))

        nov_projekt = SeznamProjektov(
            naziv_projekta=naziv_projekta,
            narocnik=narocnik,
            company_id=current_user.company_id
        )
        db.session.add(nov_projekt)
        db.session.commit()
        flash(f'Projekt "{naziv_projekta}" uspešno dodan.')
        return redirect(url_for('seznam_projektov'))

    return render_template('dodaj_projekt.html')

@app.route('/uredi_projekt/<int:id_proj>', methods=['GET', 'POST'])
@login_required
def uredi_projekt(id_proj):
    projekt = SeznamProjektov.query.filter_by(
        idProjekta=id_proj,
        company_id=current_user.company_id
    ).first_or_404()

    if request.method == 'POST':
        novi_naziv = request.form.get('naziv_projekta')
        novi_narocnik = request.form.get('narocnik')

        if not novi_naziv:
            flash('Naziv projekta je obvezen.', 'error')
            return redirect(url_for('uredi_projekt', id_proj=id_proj))
        
        projekt.naziv_projekta = novi_naziv
        projekt.narocnik = novi_narocnik
        db.session.commit()
        flash('Projekt uspešno posodobljen.')
        return redirect(url_for('seznam_projektov'))

    return render_template('uredi_projekt.html', projekt=projekt)

@app.route('/izbrisi_projekt/<int:id_proj>', methods=['POST'])
@login_required
def izbrisi_projekt(id_proj):
    projekt = SeznamProjektov.query.filter_by(
        idProjekta=id_proj,
        company_id=current_user.company_id
    ).first_or_404()
    db.session.delete(projekt)
    db.session.commit()
    flash('Projekt izbrisan.')
    return redirect(url_for('seznam_projektov'))

@app.route('/admin_meni', methods=['GET', 'POST'])
@login_required
def admin_meni():
   
    if current_user.role != 'admin':
        flash('Dostop zavrnjen. Niste admin.', 'error')
        return redirect(url_for('index'))

    podjetje = current_user.podjetje
    if not podjetje:
        flash('Niste povezani z nobenim podjetjem.', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
 
        if 'novo_ime' in request.form:
    
            novo_ime = request.form.get('novo_ime')
            if not novo_ime:
                flash('Naziv podjetja ne sme biti prazen.', 'error')
                return redirect(url_for('admin_meni'))
            podjetje.nazivPodjetja = novo_ime
            db.session.commit()
            flash('Naziv podjetja uspešno posodobljen.')
            return redirect(url_for('admin_meni'))

    
        elif 'logo_file' in request.files:
            logo_file = request.files['logo_file']
            if logo_file:
            
                filename = f"company_{podjetje.idPodjetja}.png"
              
                save_path = os.path.join(app.static_folder, 'logos', filename)
                logo_file.save(save_path)

            
                podjetje.logo_filename = filename
                db.session.commit()

                flash('Logotip uspešno naložen.')
            else:
                flash('Niste izbrali datoteke za logotip.', 'error')

        return redirect(url_for('admin_meni'))


    return render_template('admin_meni.html', podjetje=podjetje)




@app.route('/registriraj_podjetje', methods=['GET', 'POST'])
def registriraj_podjetje():
    if request.method == 'POST':
        naziv = request.form.get('naziv_podjetja')
        admin_username = request.form.get('admin_username')
        admin_password = request.form.get('admin_password')

        if not naziv or not admin_username or not admin_password:
            flash('Vnesite vse podatke.', 'error')
            return redirect(url_for('registriraj_podjetje'))

        podjetje_key = secrets.token_hex(8)

        novo_podjetje = Podjetje(
            nazivPodjetja=naziv,
            kljucPodjetja=podjetje_key
        )
        db.session.add(novo_podjetje)
        db.session.flush()

     
        admin_user = Uporabnik(
            username=admin_username,
            role='admin',
            company_id=novo_podjetje.idPodjetja,
            approved=True   
        )
        admin_user.set_password(admin_password)
        db.session.add(admin_user)

        db.session.commit()

        flash(f'Podjetje "{naziv}" registrirano. Ključ podjetja je: {podjetje_key}.')
        flash('Prijavite se zdaj z admin računom.')
        return redirect(url_for('prijava'))

    return render_template('registriraj_podjetje.html')

@app.route('/admin_requests')
@login_required
def admin_requests():
    if current_user.role != 'admin':
        flash('Dostop zavrnjen. Niste admin.')
        return redirect(url_for('index'))


    pending_users = Uporabnik.query.filter_by(approved=False).all()
    return render_template('admin_requests.html', pending_users=pending_users)


@app.route('/approve_user/<int:user_id>', methods=['POST'])
@login_required
def approve_user(user_id):
    if current_user.role != 'admin':
        flash('Dostop zavrnjen.')
        return redirect(url_for('index'))

    user_to_approve = Uporabnik.query.get_or_404(user_id)
    user_to_approve.approved = True
    db.session.commit()
    flash(f'Uporabnik {user_to_approve.username} je potrjen.')
    return redirect(url_for('admin_requests'))


@app.route('/reject_user/<int:user_id>', methods=['POST'])
@login_required
def reject_user(user_id):
    if current_user.role != 'admin':
        flash('Dostop zavrnjen.')
        return redirect(url_for('index'))

    user_to_reject = Uporabnik.query.get_or_404(user_id)

    db.session.delete(user_to_reject)
    db.session.commit()
    flash('Uporabnik zavrnjen in izbrisan.')
    return redirect(url_for('admin_requests'))

@app.route('/admin_users')
@login_required
def admin_users():

    if current_user.role != 'admin':
        flash('Dostop zavrnjen. Niste admin.')
        return redirect(url_for('index'))


    all_users = Uporabnik.query.filter_by(company_id=current_user.company_id).all()
    return render_template('admin_users.html', all_users=all_users)

@app.route('/update_user_access/<int:user_id>', methods=['POST'])
@login_required
def update_user_access(user_id):
 
    if current_user.role != 'admin':
        flash('Dostop zavrnjen. Niste admin.')
        return redirect(url_for('index'))

    user = Uporabnik.query.get_or_404(user_id)

    if user.company_id != current_user.company_id:
        flash('Ni dovoljenja za urejanje uporabnika iz drugega podjetja.', 'error')
        return redirect(url_for('admin_users'))


    new_approved = request.form.get('approved')  
    new_role = request.form.get('role')          


    user.approved = True if new_approved == 'on' else False
    user.role = new_role  

    db.session.commit()
    flash(f'Uporabnik {user.username} posodobljen (approved={user.approved}, role={user.role}).')
    return redirect(url_for('admin_users'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash('Dostop zavrnjen.')
        return redirect(url_for('index'))

    user = Uporabnik.query.get_or_404(user_id)
    if user.company_id != current_user.company_id:
        flash('Ni dovoljenja za brisanje tujega uporabnika.', 'error')
        return redirect(url_for('admin_users'))


    if user.id == current_user.id:
        flash('Ne morete izbrisati samega sebe!', 'error')
        return redirect(url_for('admin_users'))

    db.session.delete(user)
    db.session.commit()
    flash(f'Uporabnik {user.username} izbrisan.')
    return redirect(url_for('admin_users'))

@app.route('/setup_2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    user = current_user

    if request.method == 'POST':
       
        if not user.otp_secret:
            user.otp_secret = pyotp.random_base32()
            db.session.commit()

   
        totp_uri = f"otpauth://totp/MojaAplikacija:{user.username}?secret={user.otp_secret}&issuer=MojaAplikacija"

    
        qr_img = qrcode.make(totp_uri)
        buf = io.BytesIO()
        qr_img.save(buf, 'PNG')
        buf.seek(0)

        return send_file(buf, mimetype='image/png')

  
    return render_template('setup_2fa.html')

def verify_2fa():
  
    user_id = session.get('2fa_user_id')
    if not user_id:
        flash('Nimate aktivne 2FA seje. Najprej se prijavite.')
        return redirect(url_for('prijava'))

    user = Uporabnik.query.get(user_id)
    if not user or not user.two_factor_enabled:
        flash('User nima vklopljene 2FA ali ne obstaja.')
        return redirect(url_for('prijava'))

    if request.method == 'POST':
        code = request.form.get('code')
        totp = pyotp.TOTP(user.otp_secret)
        if totp.verify(code):
       
            login_user(user)
         
            session.pop('2fa_user_id', None)
            flash('2FA uspešna, dobrodošli!')
            return redirect(url_for('index'))
        else:
            flash('Nepravilna 2FA koda.')
            return redirect(url_for('verify_2fa'))

    return render_template('verify_2fa.html')


@app.route('/enable_2fa', methods=['GET', 'POST'])
@login_required
def enable_2fa():
    if not current_user.otp_secret:
        flash('Najprej generirajte QR kodo (setup_2fa).')
        return redirect(url_for('setup_2fa'))

    if request.method == 'POST':
        code = request.form.get('code')
        totp = pyotp.TOTP(current_user.otp_secret)
        if totp.verify(code):
            current_user.two_factor_enabled = True
            db.session.commit()
            flash('2FA je uspešno aktiviran.')
            return redirect(url_for('index'))
        else:
            flash('Neveljavna koda, poskusite znova.')
            return redirect(url_for('enable_2fa'))

    return render_template('enable_2fa.html')


@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():

    user_id = session.get('2fa_user_id')
    if not user_id:
        flash('Nimate aktivne 2FA seje. Najprej se prijavite.')
        return redirect(url_for('prijava'))

    user = Uporabnik.query.get(user_id)
    if not user or not user.two_factor_enabled:
        flash('User nima vklopljene 2FA ali ne obstaja.')
        return redirect(url_for('prijava'))

    if request.method == 'POST':
        code = request.form.get('code')
        totp = pyotp.TOTP(user.otp_secret)
        if totp.verify(code):
         
            login_user(user)
       
            session.pop('2fa_user_id', None)
            flash('2FA uspešna, dobrodošli!')
            return redirect(url_for('index'))
        else:
            flash('Nepravilna 2FA koda.')
            return redirect(url_for('verify_2fa'))

    return render_template('verify_2fa.html')

@app.route('/disable_2fa', methods=['POST'])
@login_required
def disable_2fa():
    current_user.two_factor_enabled = False
    current_user.otp_secret = None
    db.session.commit()
    flash('2FA je onemogočen in skrivnost zbrisana.')
    return redirect(url_for('index'))





if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        db.session.commit()

    app.run(debug=True)
