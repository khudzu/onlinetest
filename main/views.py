from django.conf import settings
from django.http import FileResponse, Http404
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.http import HttpResponseRedirect
from django.contrib.auth import authenticate, login, logout
from main.functions.functions import handle_uploaded_file

# Create your views here.

from .forms import PostForm, LoginForm
from .models import PostModel
from sympy import *
import cv2
import numpy as np
from pathlib import Path
from io import BytesIO
from urllib.parse import quote
from uuid import uuid4

STATIC_IMAGE_DIR = Path(__file__).resolve().parent.parent / 'static' / 'img'
ENCRYPTED_IMAGE_DIR = settings.MEDIA_ROOT / 'encrypted_images'


def get_image_url(image_name):
	filename = Path(str(image_name)).name
	if not filename.endswith('.png'):
		filename = f'{filename}.png'
	return f'/encrypted-images/{quote(filename)}'


def get_decrypted_image_url(image_name):
	filename = Path(str(image_name)).name
	if not filename.endswith('.png'):
		filename = f'{filename}.png'
	return f'/decrypted-images/{quote(filename)}'


def find_stored_image(filename):
	if not filename.endswith('.png'):
		filename = f'{filename}.png'

	for image_dir in [ENCRYPTED_IMAGE_DIR, STATIC_IMAGE_DIR]:
		image_path = image_dir / filename
		if image_path.exists():
			return image_path

	return None

def get_secured_image(img, action, a, b, d):
    #---------------Read Image to Encrypt---------------
    Mod = 256
    a=int(a)
    b=int(b)
    d=int(d)
    rows, cols, ch = img.shape
    q = np.zeros([rows, cols, ch])
    key = np.array([[1,a],[b,a*b+1]])
    keyinvers=np.linalg.inv(key)
    keyinvers = keyinvers.astype(int)
    i=0
    if action == 'ENKRIPSI':
        if cols % 2 == 1:
            img = cv2.copyMakeBorder(img, 0, 0, 0, 1, cv2.BORDER_REPLICATE)
            rows, cols, ch = img.shape
            q = np.zeros([rows, cols, ch])
        # Enkripsi Hill Cipher
        for x in range (0, rows):
            for y in range (0, cols, 2):
                m=img[x,y:y+2,:]
                n=(np.matmul(key,m % Mod)) % Mod
                q[x,y:y+2,:]=n
        img=q.astype(np.uint8)
        #Enkripsi Arnold Cat Map
        while i<d:
            rows, cols, ch = img.shape
            if (rows == cols):
                n = rows
                img2 = np.zeros([rows, cols, ch])
                for x in range(0, rows):
                    for y in range(0, cols):
                        k=[x,y]
                        l=np.matmul(key,k)%n
                        img2[x,y] = img[l[0],l[1]]
                img=img2
            i=i+1
        encrypted=img.astype(np.uint8)
        return encrypted
    elif action == 'DEKRIPSI':
        #Dekripsi Arnold Cat Map
        while i<d:
            rows, cols, ch = img.shape
            if (rows == cols):
                n = rows
                img2 = np.zeros([rows, cols, ch])
                for x in range(0, rows):
                    for y in range(0, cols):
                        k=[x,y]
                        l=np.matmul(keyinvers,k)%n
                        img2[x,y] = img[l[0],l[1]]
                img=img2
            i=i+1
        img2=img.astype(np.uint8)
        #Dekripsi Hill Cipher
        rows, cols, ch = img.shape
        p = np.zeros([rows, cols, ch])
        for x in range (0, rows):
            for y in range (0, cols, 2):
                m=img[x,y:y+2,:]
                n=(np.matmul(keyinvers,m % Mod)) % Mod
                p[x,y:y+2,:]=n
        decrypted=p.astype(np.uint8)
        return decrypted


def get_secured_data(p):
	if len(p)%2==1:
		p=p+' '
	K = Matrix(([2, 1], [5, 3]))
	Km = Matrix(([1, 2], [3, 7]))

	c = ''
	cm = ''
	i = 0
	while i < len(p):
		P = Matrix((ord(p[i])-32, ord(p[i + 1])-32))
		C = Km*(K * P)
		cm = cm + chr((C[0] % 97)+32) + chr((C[1] % 97)+32)
		i = i + 2
	return cm

def get_data(p):
	if len(p)%2==1:
		p=p+' '
	K = Matrix(([2, 1], [5, 3]))
	Km = Matrix(([1, 2], [3, 7]))

	c = ''
	cm = ''
	i = 0
	while i < len(p):
		P = Matrix((ord(p[i])-32, ord(p[i + 1])-32))
		C = K.inv()*(Km.inv() * P)
		cm = cm + chr((C[0] % 97)+32) + chr((C[1] % 97)+32)
		i = i + 2
	return cm

def data(request):
	posts = PostModel.objects.all()

	for post in posts:
		post.image=get_decrypted_image_url(post.image)
		post.Nama=get_data(post.Nama)
		post.Alamat=get_data(post.Alamat)
		post.NIK=get_data(post.NIK)
	context = {
		'page_title':'Data anda akan tersimpan dengan aman',
		'posts':posts,
	}

	return render(request,'main/home.html',context)

def home(request):
	posts = PostModel.objects.all()
	for post in posts:
		post.image=get_image_url(post.image)
		post.Nama=post.Nama
		post.Alamat=post.Alamat
		post.NIK=post.NIK
	context = {
		'page_title':'Data anda akan tersimpan dengan aman',
		'posts':posts,
	}
	return render(request,'main/home.html',context)

def create(request):
	post_form = PostForm()

	if request.method == 'POST':
		post_form = PostForm(request.POST, request.FILES)
		if post_form.is_valid():
			uploaded_image = post_form.cleaned_data['image']
			image_bytes = np.frombuffer(uploaded_image.read(), np.uint8)
			img = cv2.imdecode(image_bytes, cv2.IMREAD_COLOR)

			if img is None:
				post_form.add_error('image', 'File gambar tidak bisa dibaca.')
			else:
				secured_image_name = f'{uuid4().hex}.png'
				imc = get_secured_image(img, 'ENKRIPSI', 2, 3, 2)

				ENCRYPTED_IMAGE_DIR.mkdir(parents=True, exist_ok=True)
				cv2.imwrite(str(ENCRYPTED_IMAGE_DIR / secured_image_name), imc)

				PostModel.objects.create(
						Nama 		= get_secured_data(post_form.cleaned_data['nama']),
						Password	= get_secured_data(post_form.cleaned_data['password']),
						NIK		= get_secured_data(post_form.cleaned_data['nik']),
						image 		= secured_image_name,
						Alamat		= get_secured_data(post_form.cleaned_data['alamat']),

					)

				return HttpResponseRedirect('/data/')


	context = {
		'page_title':'Pendaftaran',
		'post_form':post_form
	}

	return render(request,'main/create.html',context)


def encrypted_image(request, filename):
	image_path = find_stored_image(filename)
	if image_path:
		return FileResponse(open(image_path, 'rb'), content_type='image/png')

	raise Http404('Gambar tidak ditemukan.')


def decrypted_image(request, filename):
	image_path = find_stored_image(filename)
	if not image_path:
		raise Http404('Gambar tidak ditemukan.')

	encrypted = cv2.imread(str(image_path))
	if encrypted is None:
		raise Http404('Gambar tidak bisa dibaca.')

	decrypted = get_secured_image(encrypted, 'DEKRIPSI', 2, 3, 2)
	ok, buffer = cv2.imencode('.png', decrypted)
	if not ok:
		raise Http404('Gambar tidak bisa didekripsi.')

	return HttpResponse(BytesIO(buffer).getvalue(), content_type='image/png')


def login(request):
	login_form = LoginForm()
	context = {
		'page_title': 'Login',
		'login_form':login_form
	}
	user=None
	if request.method == 'GET':
		if request.user.is_authenticated == True:
			return redirect('/login')
		else:
			return render(request, 'main/login.html', context)
	elif request.method == "POST":
		username_login = request.POST['nama']
		password_login = request.POST['password']

		user = authenticate(request, username=username_login, password=password_login)
		print(user)
		if user is not None:
			login(request, user)
			return redirect('/data')
		else:
			print(username_login)
			print(password_login)
			print('Username atau password anda salah, silahkan masukkan dengan benar!')
			return redirect('/data')
	return render(request, 'main/login.html', context)



def logout(request):
	login_form = LoginForm()
	context = {
		'page_title': 'Logout',
		'login_form':login_form
	}
	request.user.is_authenticated == False
	return redirect('/')

