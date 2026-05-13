from django import forms


class PostForm(forms.Form):
	nama		= forms.CharField(max_length = 20)
	password = forms.CharField(max_length=20)
	nik	= forms.CharField(max_length = 20)
	image = forms.ImageField(
		label='Foto',
		required=True,
	)
	alamat		= forms.CharField(
		widget = forms.Textarea
		)

class LoginForm(forms.Form):
	nama		= forms.CharField(max_length = 20)
	password 	= forms.CharField(max_length=20, widget=forms.PasswordInput)


class DecryptionKeyForm(forms.Form):
	decryption_key = forms.CharField(
		label='Kunci Dekripsi',
		max_length=128,
		widget=forms.PasswordInput,
	)
