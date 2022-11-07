from django.db import models

# Create your models here.

class PostModel(models.Model):
	Nama		= models.CharField(max_length = 20)
	Password	= models.CharField(max_length = 20)
	NIK         = models.CharField(max_length = 20)
	image 		= models.ImageField(blank=True, default='default.png', null=True, upload_to='static/img/')
	Alamat		= models.TextField()

	published	= models.DateTimeField(auto_now_add = True)
	updated		= models.DateTimeField(auto_now = True)

	def __str__(self):
		return "{}. {}".format(self.id, self.Nama)