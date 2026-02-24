import datetime
import tkinter as tk
from tkinter import messagebox, filedialog
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

class RaqamliImzoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Raqamli Imzo Dasturi (X.509)")
        # Oyna o'lchami hamma tugmalar sig'ishi uchun moslandi
        self.root.geometry("500x800") 
        self.root.configure(bg="#003366") 

        self.private_key = None
        self.certificate = None
        self.csr = None

        self.setup_ui()

    def setup_ui(self):
        # Sarlavha: RAQAMLI IMZO DASTURI
        header = tk.Frame(self.root, bg="#002244", height=80)
        header.pack(fill="x")
        tk.Label(header, text="RAQAMLI IMZO DASTURI", font=("Segoe UI", 18, "bold"), 
                 bg="#002244", fg="#87CEEB").pack(pady=20) 

        main_frame = tk.Frame(self.root, bg="#003366")
        main_frame.pack(padx=40, pady=5, fill="both", expand=True)

        # Maydonlar tartibi: Davlat -> Viloyat -> Shahar -> Tashkilot -> Bo'lim -> Ism
        self.field_labels = [
            ("Davlat kodi (C - masalan, UZ):", "C"),
            ("Viloyat (State/Province):", "S"),
            ("Shahar/Tuman (Locality):", "L"),
            ("Tashkilot nomi (Organization):", "O"),
            ("Bo'lim nomi (Organizational Unit):", "OU"),
            ("To'liq ism (Common Name):", "CN")
        ]

        self.entries = {}
        for label_text, key in self.field_labels:
            lbl = tk.Label(main_frame, text=label_text, bg="#003366", fg="#ffffff", 
                           font=("Segoe UI", 9, "bold"))
            lbl.pack(anchor="w", pady=(8, 0))
            
            entry = tk.Entry(main_frame, bd=0, bg="#004080", fg="white", 
                             insertbackground="white", font=("Segoe UI", 11))
            entry.pack(fill="x", pady=(2, 0), ipady=7)
            
            # Ochiq ko'k rangli chiziq
            tk.Frame(main_frame, height=2, bg="#87CEEB").pack(fill="x", pady=(0, 5))
            self.entries[key] = entry

        # Tugmalar paneli
        btn_frame = tk.Frame(self.root, bg="#003366")
        btn_frame.pack(pady=20, padx=40, fill="x")

        # Ranglar (Ochiq ko'k va pastel)
        sky_blue = "#87CEEB"
        
        # 1. Asosiy yaratish tugmasi
        self.create_btn(btn_frame, "✨ IMZO VA KALITLARNI YARATISH", sky_blue, "#003366", self.create_all)
        
        # 2. Saqlash tugmalari
        self.create_btn(btn_frame, "💾 Sertifikatni saqlash (.crt)", "#98FB98", "black", self.save_cert) 
        self.create_btn(btn_frame, "🔑 Shaxsiy kalitni saqlash (.key)", "#F0E68C", "black", self.save_key) 
        self.create_btn(btn_frame, "📝 So'rovni saqlash (.csr)", "#DDA0DD", "black", self.save_csr) 
        self.create_btn(btn_frame, "📄 PEM formatda saqlash (.pem)", "#B0E0E6", "black", self.save_pem) 

    def create_btn(self, parent, text, bg_color, fg_color, command):
        btn = tk.Button(parent, text=text, command=command, bg=bg_color, fg=fg_color,
                        font=("Segoe UI", 9, "bold"), bd=0, height=2, 
                        activebackground="#5F9EA0", cursor="hand2")
        btn.pack(fill="x", pady=4) 

    def create_all(self):
        try:
            # Ma'lumotlarni tekshirish va tozalash
            data = {k: v.get().strip() for k, v in self.entries.items()}
            
            for key, val in data.items():
                if not val:
                    raise ValueError("Iltimos, barcha maydonlarni to'ldiring!")

            # Davlat kodi tekshiruvi (faqat 2 ta belgi bo'lishi shart)
            if len(data['C']) != 2:
                raise ValueError("Davlat kodi faqat 2 ta harfdan iborat bo'lishi kerak (masalan: UZ)")

            # RSA kalit yaratish
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            
            # Sertifikat sub'ekti (Subject)
            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, data['C'].upper()),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, data['S']),
                x509.NameAttribute(NameOID.LOCALITY_NAME, data['L']),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, data['O']),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, data['OU']),
                x509.NameAttribute(NameOID.COMMON_NAME, data['CN']),
            ])

            now = datetime.datetime.now(datetime.timezone.utc)
            
            # Sertifikatni shakllantirish
            self.certificate = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                subject
            ).public_key(
                self.private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                now
            ).not_valid_after(
                now + datetime.timedelta(days=365)
            ).sign(self.private_key, hashes.SHA256())

            # CSR yaratish
            self.csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(self.private_key, hashes.SHA256())

            messagebox.showinfo("Muvaffaqiyat", "Raqamli imzo va barcha fayllar tayyorlandi!")
        except Exception as e:
            messagebox.showerror("Xato", str(e))

    # Saqlash funksiyalari
    def _save_file(self, obj, ext, label):
        if not obj: 
            messagebox.showwarning("!", "Avval imzoni yarating!")
            return
        path = filedialog.asksaveasfilename(defaultextension=ext, filetypes=[(label, f"*{ext}")])
        if path:
            with open(path, "wb") as f:
                f.write(obj.public_bytes(serialization.Encoding.PEM))
            messagebox.showinfo("OK", f"{label} saqlandi!")

    def save_cert(self): self._save_file(self.certificate, ".crt", "Sertifikat")
    def save_csr(self): self._save_file(self.csr, ".csr", "So'rov fayli")
    def save_pem(self): self._save_file(self.certificate, ".pem", "PEM fayli")
    
    def save_key(self): 
        if not self.private_key: 
            messagebox.showwarning("!", "Kalit mavjud emas!")
            return
        path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Kalit fayli", "*.key")])
        if path:
            with open(path, "wb") as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            messagebox.showinfo("OK", "Shaxsiy kalit (.key) saqlandi!")

if __name__ == "__main__":
    root = tk.Tk()
    app = RaqamliImzoApp(root)
    root.mainloop()
