from django.db import models
from django.contrib.auth.models import User

# Create your models here.

class PostModel(models.Model):
	owner		= models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
	Nama		= models.TextField()
	# Kept for backwards compatibility with older records.
	Password	= models.TextField(blank=True, default='')
	NIK         = models.TextField()
	no_kk       = models.TextField(blank=True, default='')
	tempat_lahir = models.TextField(blank=True, default='')
	tanggal_lahir = models.TextField(blank=True, default='')
	jenis_kelamin = models.TextField(blank=True, default='')
	nama_ayah   = models.TextField(blank=True, default='')
	nik_ayah    = models.TextField(blank=True, default='')
	nama_ibu    = models.TextField(blank=True, default='')
	nik_ibu     = models.TextField(blank=True, default='')
	agama       = models.TextField(blank=True, default='')
	pendidikan  = models.TextField(blank=True, default='')
	jenis_pekerjaan = models.TextField(blank=True, default='')
	status_perkawinan = models.TextField(blank=True, default='')
	status_hubungan_keluarga = models.TextField(blank=True, default='')
	kewarganegaraan = models.TextField(blank=True, default='')
	no_paspor   = models.TextField(blank=True, default='')
	no_kitap    = models.TextField(blank=True, default='')
	image 		= models.CharField(max_length=255, blank=True, default='default.png', null=True)
	image_ciphertext = models.TextField(blank=True, default='')
	Alamat		= models.TextField()
	aes_key		= models.TextField(blank=True, default='')
	key_salt	= models.CharField(max_length=64, blank=True, default='')

	published	= models.DateTimeField(auto_now_add = True)
	updated		= models.DateTimeField(auto_now = True)

	def __str__(self):
		return "{}. {}".format(self.id, self.Nama)
