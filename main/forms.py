from django import forms


class PostForm(forms.Form):
	nama		= forms.CharField(max_length = 20)
	password = forms.CharField(max_length=20)
	nik	= forms.CharField(max_length = 20)
	image = forms.ImageField(
		label='Citra Digital',
		required=True,
	)
	alamat		= forms.CharField(
		widget = forms.Textarea
		)

class LoginForm(forms.Form):
	nama		= forms.CharField(max_length = 20)
	password 	= forms.CharField(max_length=20)