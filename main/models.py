from django.db import models

# Create your models here.

class PostModel(models.Model):
	Nama		= models.TextField()
	Password	= models.TextField()
	NIK         = models.TextField()
	image 		= models.CharField(max_length=255, blank=True, default='default.png', null=True)
	Alamat		= models.TextField()
	aes_key		= models.TextField(blank=True, default='')

	published	= models.DateTimeField(auto_now_add = True)
	updated		= models.DateTimeField(auto_now = True)

	def __str__(self):
		return "{}. {}".format(self.id, self.Nama)
