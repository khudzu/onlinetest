from django import forms


class PostForm(forms.Form):
	nama = forms.CharField(label='Nama Lengkap', max_length=100)
	nik = forms.CharField(label='NIK', max_length=20)
	no_kk = forms.CharField(label='No. KK', max_length=20)
	tempat_lahir = forms.CharField(label='Tempat Lahir', max_length=100)
	tanggal_lahir = forms.DateField(
		label='Tanggal Lahir',
		widget=forms.DateInput(attrs={'type': 'date'}),
	)
	jenis_kelamin = forms.ChoiceField(
		label='Jenis Kelamin',
		choices=(('', 'Pilih jenis kelamin'), ('L', 'Laki-laki'), ('P', 'Perempuan')),
	)
	nama_ayah = forms.CharField(label='Nama Lengkap Ayah', max_length=100)
	nik_ayah = forms.CharField(label='NIK Ayah', max_length=20)
	nama_ibu = forms.CharField(label='Nama Lengkap Ibu', max_length=100)
	nik_ibu = forms.CharField(label='NIK Ibu', max_length=20)
	agama = forms.ChoiceField(
		label='Agama',
		choices=(('', 'Pilih agama'), ('Islam', 'Islam'), ('Kristen', 'Kristen'), ('Katolik', 'Katolik'), ('Hindu', 'Hindu'), ('Buddha', 'Buddha'), ('Konghucu', 'Konghucu')),
	)
	pendidikan = forms.ChoiceField(
		label='Pendidikan',
		choices=(('', 'Pilih pendidikan'), ('Tidak/Belum Sekolah', 'Tidak/Belum Sekolah'), ('SD/Sederajat', 'SD/Sederajat'), ('SMP/Sederajat', 'SMP/Sederajat'), ('SMA/Sederajat', 'SMA/Sederajat'), ('Diploma', 'Diploma'), ('Sarjana', 'Sarjana'), ('Pascasarjana', 'Pascasarjana')),
	)
	jenis_pekerjaan = forms.CharField(label='Jenis Pekerjaan', max_length=100)
	status_perkawinan = forms.ChoiceField(
		label='Status Perkawinan',
		choices=(('', 'Pilih status perkawinan'), ('Belum Kawin', 'Belum Kawin'), ('Kawin', 'Kawin'), ('Cerai Hidup', 'Cerai Hidup'), ('Cerai Mati', 'Cerai Mati')),
	)
	status_hubungan_keluarga = forms.ChoiceField(
		label='Status Hubungan dalam Keluarga',
		choices=(('', 'Pilih hubungan keluarga'), ('Kepala Keluarga', 'Kepala Keluarga'), ('Suami', 'Suami'), ('Istri', 'Istri'), ('Anak', 'Anak'), ('Orang Tua', 'Orang Tua'), ('Lainnya', 'Lainnya')),
	)
	kewarganegaraan = forms.ChoiceField(
		label='Kewarganegaraan',
		choices=(('WNI', 'WNI'), ('WNA', 'WNA')),
	)
	no_paspor = forms.CharField(label='No. Paspor', max_length=50, required=False)
	no_kitap = forms.CharField(label='No. KITAP', max_length=50, required=False)
	alamat = forms.CharField(label='Alamat', widget=forms.Textarea)
	rt = forms.CharField(label='RT', max_length=3)
	rw = forms.CharField(label='RW', max_length=3)
	desa_kelurahan = forms.CharField(label='Desa/Kelurahan', max_length=100)
	kecamatan = forms.CharField(label='Kecamatan', max_length=100)
	kabupaten_kota = forms.CharField(label='Kabupaten/Kota', max_length=100)
	kode_pos = forms.CharField(label='Kode Pos', max_length=5)
	provinsi = forms.CharField(label='Provinsi', max_length=100)
	nama_kepala_desa = forms.CharField(label='Nama Kepala Desa/Lurah', max_length=100)
	image = forms.ImageField(label='Foto', required=True)


class LoginForm(forms.Form):
	nama = forms.CharField(max_length=20)
	password = forms.CharField(max_length=20, widget=forms.PasswordInput)


class DecryptionKeyForm(forms.Form):
	decryption_key = forms.CharField(
		label='Kunci Dekripsi',
		max_length=128,
		widget=forms.PasswordInput,
	)
