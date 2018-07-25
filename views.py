import Cookie
import md5

from django.shortcuts import render, get_object_or_404
from django.http import HttpResponseRedirect, HttpResponse, Http404
from django.urls import reverse
from django.core.urlresolvers import reverse_lazy
from .models import Person, Admin, Professor, User, Quiz, Question, Choice, Archive

def first_question(quiz_id):
	quiz = Quiz.objects.get(id=quiz_id)
	q = False
	for q in quiz.question_set.all():
		break
	return q

def next_question(question_id):
	question = get_object_or_404(Question, pk=question_id)
	quiz = question.quiz
	cmp = 0
	for q in quiz.question_set.all():
		if cmp == 1:
			break
		if q.id == question.id:
			cmp += 1
	return q

def last_question(quiz_id):
	cmp = 0
	quiz = Quiz.objects.get(id=quiz_id)
	for q in quiz.question_set.all():
		cmp += 1
		if cmp == quiz.question_set.count():
			break
	return q

def not_connected(r_s):
	if 'id' in r_s:
		return False
	else:
		return True

def get_person(request, id_pers, type_person):
	request.session.set_expiry(60*60*3) #for 3 hours
	is_true = False
	if type_person == 'admin':
		for u in Admin.objects.all():
			if u.id == id_pers:
				is_true = True
		if is_true:
			person = Admin.objects.get(id=id_pers)
			request.session['type'] = 'admin'
		else:
			return "error"
	elif type_person == 'professor':
		for u in Professor.objects.all():
			if u.id == id_pers:
				is_true = True
		if is_true:
			person = Professor.objects.get(id=id_pers)
			request.session['type'] = 'professor'
		else:
			return "error"
	else:
		for u in User.objects.all():
			if u.id == id_pers:
				is_true = True
		if is_true:
			person = User.objects.get(id=id_pers)
			request.session['type'] = 'user'
		else:
			return "error"
	return person

def quiz_iscomplete(quiz_id):
	try:
		quiz = Quiz.objects.get(id=quiz_id)
	except (KeyError, Quiz.DoesNotExist):
		return False
	else:
		if quiz.question_set.count() < 1:
			return False
		for qst in quiz.question_set.all():
			if qst.choice_set.count() < 2:
				return False
		return True

def logout(request):
	try:
		del request.session['id']
	except KeyError:
		return HttpResponseRedirect(reverse('www:index'))
	return HttpResponseRedirect(reverse('www:index'))

####################################################################################################################################
######################################################### For all ##################################################################
####################################################################################################################################

def index(request):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/index.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/index.html')
	else:
		response = render(request, 'www/index.html', {
			'user': get_person(request, request.session['id'], request.session['type']),
			'connected': request.session['type'],
			})
		user = get_person(request, request.session['id'], request.session['type'])
		if user.type_person == 'admin':
			return HttpResponseRedirect(reverse('www:indexAdmin'))
		elif user.type_person == 'professor':
			return HttpResponseRedirect(reverse('www:indexProf'))
	return response

def quiz(request):
	if not_connected(request.session):
		response = render(request, 'www/quiz.html', {
			'all_quizs': Quiz.objects.all,
			})
	else:
		response = render(request, 'www/quiz.html', {
			'all_quizs': Quiz.objects.all,
			'user': get_person(request, request.session['id'], request.session['type']),
			'connected': request.session['type'],
			})
	return response

def login_page(request):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/login.html', {
				'error_message': request.session['error'],
				'auth_user': request.session['username'],
				})
			del request.session['error']
			del request.session['username']
		else:
			response = render(request, 'www/login.html')
	else:
		response = render(request, 'www/index.html', {
			'user': get_person(request, request.session['id'], request.session['type']),
			'connected': request.session['type'],
			})
		user = get_person(request, request.session['id'], request.session['type'])
		if user.type_person == 'admin':
			return HttpResponseRedirect(reverse('www:indexAdmin'))
		elif user.type_person == 'professor':
			return HttpResponseRedirect(reverse('www:indexProf'))
	return response

def login(request):
	try:
		username = request.POST['username']
		password = request.POST['password']
		type_person = request.POST['type']
		#person = get_object_or_404(Person, username=username)
		person = Person.objects.get(username=username)
		person_id = person.id
		person = get_person(request, person_id, type_person)
	except(KeyError, Person.DoesNotExist):
		request.session['error'] = 'check your username / password or account type.'
		return HttpResponseRedirect(reverse('www:login_page'))
	else:
		request.session['username'] = username
		if person == 'error':
			request.session['error'] = 'check your username / password or account type.'
			return HttpResponseRedirect(reverse('www:login_page'))
		password = md5.new(password).hexdigest()
		if person.username == username and person.password == password and person.type_person == type_person:
			if not person.is_valid:
				request.session['error'] = ' your account is locked.'
				return HttpResponseRedirect(reverse('www:login_page'))
			if type_person == 'admin':
				request.session['type'] = 'admin'
				response = HttpResponseRedirect(reverse('www:indexAdmin'))
			elif type_person == 'professor':
				request.session['type'] = 'professor'
				response = HttpResponseRedirect(reverse('www:indexProf'))
			else:
				request.session['type'] = 'user'
				response = HttpResponseRedirect(reverse('www:index'))
			#response.set_cookie('username', user.username)
			#response.delete_cookie('username')
			request.session.set_expiry(60*60*2) #for 2 hours
			request.session['id'] = person.id
			return response
		else:
			request.session['error'] = 'check your username / password or account type.'
			return HttpResponseRedirect(reverse('www:login_page'))

def register_page(request):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/register.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/register.html')
	else:
		response = render(request, 'www/index.html', {
			'user': get_person(request, request.session['id'], request.session['type']),
			'connected': request.session['type'],
			})
		user = get_person(request, request.session['id'], request.session['type'])
		if user.type_person == 'admin':
			return HttpResponseRedirect(reverse('www:indexAdmin'))
		elif user.type_person == 'professor':
			return HttpResponseRedirect(reverse('www:indexProf'))
	return response

def register(request):
	try:
		username = request.POST['username']
		email = request.POST['email']
		password = request.POST['password']
		cpassword = request.POST['confirm_password']
		type_person = request.POST['type']
		cin = request.POST['cin']
	except(KeyError):
		request.session['error'] = 'There is something wrong!'
		return HttpResponseRedirect(reverse('www:register_page'))
	else:
		error = ''
		for person in Person.objects.all():
			if person.username == username:
				error = 'username already exist'
			elif person.email == email:
				error = 'email already exist'
			elif person.cin == cin:
				error = 'CIN already exist'
		if password == cpassword:
			if error:
				request.session['error'] = error
				return HttpResponseRedirect(reverse('www:register_page'))
			else:
				if type_person == 'user':
					User.objects.create(username=username,cin=cin, password=md5.new(password).hexdigest(), email=email, type_person='user')
				elif type_person == 'professor':
					Professor.objects.create(username=username,cin=cin, password=md5.new(password).hexdigest(), email=email, type_person='professor')
				else:
					Admin.objects.create(username=username,cin=cin, password=md5.new(password).hexdigest(), email=email, type_person='admin')
				return render(request, 'www/register.html', {'success': "Registration success",})
		else:
			request.session['error'] = 'Not match password.'
			return HttpResponseRedirect(reverse('www:register_page'))


####################################################################################################################################
######################################################### For Admin ################################################################
####################################################################################################################################

def indexAdmin(request):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/index.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/index.html')
		return response
	else:
		if 'success' in request.session:
			response = render(request, 'www/admin/index.html', {
				'success': request.session['success'],
				'users': User.objects.filter(type_person__startswith='user').order_by('username'),
				'profs': Professor.objects.order_by('username'),
				'admins': Admin.objects.order_by('username'),
				'user': get_person(request, request.session['id'], request.session['type']),
				'locked': Person.objects.filter(is_valid=False),
				'connected': request.session['type'],
				})
			del request.session['success']
		else:
			response = render(request, 'www/admin/index.html', {
				'users': User.objects.filter(type_person__startswith='user').order_by('username'),
				'profs': Professor.objects.order_by('username'),
				'admins': Admin.objects.order_by('username'),
				'user': get_person(request, request.session['id'], request.session['type']),
				'locked': Person.objects.filter(is_valid=False),
				'connected': request.session['type'],
				})
		user = get_person(request, request.session['id'], request.session['type'])
		if user.type_person != 'admin':
			return HttpResponseRedirect(reverse('www:index'))
	return response

def unlock(request, user_id):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/index.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/index.html')
		return response

	Person.objects.filter(id=user_id).update(is_valid=True)
	request.session['success'] = ' person unlocked.'
	return HttpResponseRedirect(reverse('www:indexAdmin'))



def add(request):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/index.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/index.html')
		return response

	if 'error' in request.session:
		response = render(request, 'www/admin/add.html', {
			'error_message': request.session['error'],
			'user': get_person(request, request.session['id'], request.session['type']),
			'connected': request.session['type'],
			'locked': Person.objects.filter(is_valid=False),
			})
		del request.session['error']
	else:
		response = render(request, 'www/admin/add.html', {
			'user': get_person(request, request.session['id'], request.session['type']),
			'connected': request.session['type'],
			'locked': Person.objects.filter(is_valid=False),
			})
	return response

def add_user(request):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/index.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/index.html')
		return response

	error = ''
	request.session['error'] = ''
	try:
		username = request.POST['username']
		cin = request.POST['cin']
		password = request.POST['password']
		cpassword = request.POST['confirm_password']
		type_person = request.POST['type']
		email = request.POST['email']
		valid = request.POST['valid']
	except(KeyError):
		request.session['error'] = "There is something wrong!"
		return HttpResponseRedirect(reverse('www:add'))
	else:
		for person in Person.objects.all():
			if person.username == username:
				error = 'username already exist'
				request.session['error'] = 'username already exist'
			elif person.email == email:
				error = 'email already exist'
				request.session['error'] = 'email already exist'
			elif person.cin == cin:
				error = 'CIN already exist'
				request.session['error'] = 'CIN already exist'
		if password == cpassword:
			if error:
				return HttpResponseRedirect(reverse('www:add'))
			else:
				if type_person == 'user':
					User.objects.create(username=username,cin=cin, password=md5.new(password).hexdigest(), email=email, type_person='user', is_valid=valid)
					request.session['success'] = ' Student added.'
				elif type_person == 'admin':
					Admin.objects.create(username=username,cin=cin, password=md5.new(password).hexdigest(), email=email, type_person='admin', is_valid=valid)
					request.session['success'] = ' Admin added.'
				else:
					Professor.objects.create(username=username,cin=cin, password=md5.new(password).hexdigest(), email=email, is_valid=valid, type_person='professor')
					request.session['success'] = ' Professor added.'
				return HttpResponseRedirect(reverse('www:indexAdmin'))
		else:
			request.session['error'] = 'not match password'
			return HttpResponseRedirect(reverse('www:add'))

def edit(request,type_person, user_id):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/index.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/index.html')
		return response

	if type_person == 'admin':
		user = get_object_or_404(Admin, id=user_id)
	elif type_person == 'professor':
		user = get_object_or_404(Professor, id=user_id)
	else:
		user = get_object_or_404(User, id=user_id)
	if 'error' in request.session:
		response = render(request, 'www/admin/edit.html', {
			'error_message': request.session['error'],
			'usr': user,
			'user': get_person(request, request.session['id'], request.session['type']),
			'connected': request.session['type'],
			'locked': Person.objects.filter(is_valid=False),
			})
		del request.session['error']
	else:
		response = render(request, 'www/admin/edit.html', {
			'usr': user,
			'user': get_person(request, request.session['id'], request.session['type']),
			'connected': request.session['type'],
			'locked': Person.objects.filter(is_valid=False),
			})
	return response

def edit_user(request,type_person, user_id):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/index.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/index.html')
		return response

	if type_person == 'admin':
		selected_user = get_object_or_404(Admin, id=user_id)
	elif type_person == 'professor':
		selected_user = get_object_or_404(Professor, id=user_id)
	else:
		selected_user = get_object_or_404(User, id=user_id)
	try:
		username = request.POST['username']
		cin = request.POST['cin']
		password = request.POST['password']
		cpassword = request.POST['confirm_password']
		#type_pers = request.POST['type']
		email = request.POST['email']
		valid = request.POST['valid']
	except(KeyError):
		request.session['error'] = "There is something wrong!"
		return HttpResponseRedirect(reverse('www:edit', kwargs={'type_person': type_person,'user_id': selected_user.id,}))
	else:
		error = ''
		for person in Person.objects.all():
			if person.username == username and person.id != selected_user.id:
				error = 'username already exist'
				request.session['error'] = 'username already exist'
			elif person.email == email and person.id != selected_user.id:
				error = 'email already exist'
				request.session['error'] = 'email already exist'
			elif person.cin == cin and person.id != selected_user.id:
				error = 'CIN already exist'
				request.session['error'] = 'CIN already exist'
		if password or cpassword:
			if password == cpassword:
				if error:
					return HttpResponseRedirect(reverse('www:edit', kwargs={'type_person': type_person,'user_id': selected_user.id,}))
				else:
					if type_person == 'admin':
						Admin.objects.filter(id=user_id).update(username=username,cin=cin, password=md5.new(password).hexdigest(), email=email, is_valid=valid)
						request.session['success'] = ' Admin updated.'
					elif type_person == 'professor':
						Professor.objects.filter(id=user_id).update(username=username,cin=cin, password=md5.new(password).hexdigest(), email=email, is_valid=valid)
						request.session['success'] = ' Professor updated.'
					else:
						User.objects.filter(id=user_id).update(username=username,cin=cin, password=md5.new(password).hexdigest(), email=email, is_valid=valid)
						request.session['success'] = ' Student updated.'
					return HttpResponseRedirect(reverse('www:indexAdmin'))
			else:
				request.session['error'] = 'not match password'
				return HttpResponseRedirect(reverse('www:edit', kwargs={'type_person': type_person,'user_id': selected_user.id,}))
		elif error:
			return HttpResponseRedirect(reverse('www:edit', kwargs={'type_person': type_person,'user_id': selected_user.id,}))
		else:
			if type_person == 'admin':
				Admin.objects.filter(id=user_id).update(username=username,cin=cin, email=email, is_valid=valid)
				request.session['success'] = ' Admin updated.'
			elif type_person == 'professor':
				Professor.objects.filter(id=user_id).update(username=username,cin=cin, email=email, is_valid=valid)
				request.session['success'] = ' Professor updated.'
			else:
				User.objects.filter(id=user_id).update(username=username,cin=cin, email=email, is_valid=valid)
				request.session['success'] = ' Student updated.'
			return HttpResponseRedirect(reverse('www:indexAdmin'))

def delete(request, user_id):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/index.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/index.html')
		return response

	user = get_object_or_404(Person, id=user_id)
	request.session['success'] = ' Actor deleted.'
	if user.id == request.session['id']:
		response = HttpResponseRedirect(reverse('www:logout'))
	else:
		response = HttpResponseRedirect(reverse('www:indexAdmin'))
	Person.objects.filter(id=user_id).delete()
	return response

####################################################################################################################################
####################################################### For Professor ##############################################################
####################################################################################################################################

def indexProf(request):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/index.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/index.html')
		return response
	else:
		if 'success' in request.session:
			response = render(request, 'www/professor/index.html', {
				'success': request.session['success'],
				'all_quizs': Quiz.objects.all,
				'user': get_person(request, request.session['id'], request.session['type']),
				'connected': request.session['type'],
				})
			del request.session['success']
		else:
			response = render(request, 'www/professor/index.html', {
				'all_quizs': Quiz.objects.all,
				'user': get_person(request, request.session['id'], request.session['type']),
				'connected': request.session['type'],
				})
		user = get_person(request, request.session['id'], request.session['type'])
		if user.type_person != 'professor':
			return HttpResponseRedirect(reverse('www:index'))
	return response

def myquizs(request):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/index.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/index.html')
		return response
	else:
		user = get_person(request, request.session['id'], request.session['type'])
		if 'success' in request.session:
			response = render(request, 'www/professor/quiz/myquizs.html', {
				'success': request.session['success'],
				'all_quizs': user.quiz_set.all,
				'user': get_person(request, request.session['id'], request.session['type']),
				'connected': request.session['type'],
				})
			del request.session['success']
		else:
			response = render(request, 'www/professor/quiz/myquizs.html', {
				'all_quizs': user.quiz_set.all,
				'user': get_person(request, request.session['id'], request.session['type']),
				'connected': request.session['type'],
				})
		user = get_person(request, request.session['id'], request.session['type'])
		if user.type_person != 'professor':
			return HttpResponseRedirect(reverse('www:index'))
	return response

def addquiz(request):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/index.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/index.html')
		return response
	else:
		if 'error' in request.session:
			response = render(request, 'www/professor/quiz/addquiz.html', {
				'error_message': request.session['error'],
				'all_quizs': Quiz.objects.all,
				'user': get_person(request, request.session['id'], request.session['type']),
				'connected': request.session['type'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/professor/quiz/addquiz.html', {
				'all_quizs': Quiz.objects.all,
				'user': get_person(request, request.session['id'], request.session['type']),
				'connected': request.session['type'],
				})
		user = get_person(request, request.session['id'], request.session['type'])
		if user.type_person != 'professor':
			return HttpResponseRedirect(reverse('www:index'))
	return response

def addquiz_confirm(request):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/index.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/index.html')
		return response

	try:
		subject = request.POST['subject']
	except(KeyError):
		request.session['error'] = "There is something wrong!"
		return HttpResponseRedirect(reverse('www:addquiz'))
	else:
		user = get_person(request, request.session['id'], request.session['type'])
		Quiz.objects.create(quiz_prof=user,quiz_subject=subject)
		request.session['success'] = ' Quiz added.'
		return HttpResponseRedirect(reverse('www:myquizs'))

def editquiz(request, quiz_id):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/index.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/index.html')
		return response
	else:
		if 'error' in request.session:
			response = render(request, 'www/professor/quiz/editquiz.html', {
				'error_message': request.session['error'],
				'quiz': get_object_or_404(Quiz, id=quiz_id),
				'user': get_person(request, request.session['id'], request.session['type']),
				'connected': request.session['type'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/professor/quiz/editquiz.html', {
				'quiz': get_object_or_404(Quiz, id=quiz_id),
				'user': get_person(request, request.session['id'], request.session['type']),
				'connected': request.session['type'],
				})
		user = get_person(request, request.session['id'], request.session['type'])
		if user.type_person != 'professor':
			return HttpResponseRedirect(reverse('www:index'))
	return response

def editquiz_confirm(request, quiz_id):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/index.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/index.html')
		return response

	try:
		subject = request.POST['subject']
	except(KeyError):
		request.session['error'] = "There is something wrong!"
		return HttpResponseRedirect(reverse('www:editquiz', kwargs={'quiz_id': quiz_id,}))
	else:
		user = get_person(request, request.session['id'], request.session['type'])
		Quiz.objects.filter(id=quiz_id).update(quiz_prof=user,quiz_subject=subject)
		request.session['success'] = ' Quiz updated.'
		return HttpResponseRedirect(reverse('www:myquizs'))

def deletequiz(request, quiz_id):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/index.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/index.html')
		return response

	quiz = get_object_or_404(Quiz, id=quiz_id)
	Quiz.objects.filter(id=quiz_id).delete()
	request.session['success'] = ' Quiz deleted.'
	return HttpResponseRedirect(reverse('www:myquizs'))

def question(request, quiz_id):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/index.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/index.html')
		return response

	if 'error' in request.session:
		response = render(request, 'www/professor/question/questions.html',{
			'user': get_person(request, request.session['id'], request.session['type']),
			'quiz': Quiz.objects.get(id=quiz_id),
			'question': Quiz.objects.get(id=quiz_id).question_set.all(),
			'error_message': request.session['error'],
			'connected': request.session['type'],
			'iscomplete': quiz_iscomplete(quiz_id),
			})
		del request.session['error']
	elif 'success' in request.session:
		response = render(request, 'www/professor/question/questions.html',{
			'user': get_person(request, request.session['id'], request.session['type']),
			'quiz': Quiz.objects.get(id=quiz_id),
			'question': Quiz.objects.get(id=quiz_id).question_set.all(),
			'success': request.session['success'],
			'connected': request.session['type'],
			'iscomplete': quiz_iscomplete(quiz_id),
			})
		del request.session['success']
	else:
		response = render(request, 'www/professor/question/questions.html',{
			'user': get_person(request, request.session['id'], request.session['type']),
			'quiz': Quiz.objects.get(id=quiz_id),
			'question': Quiz.objects.get(id=quiz_id).question_set.all(),
			'connected': request.session['type'],
			'iscomplete': quiz_iscomplete(quiz_id),
			})
	return response

def addqst(request, quiz_id):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/index.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/index.html')
		return response
	else:
		if 'error' in request.session:
			response = render(request, 'www/professor/question/addqst.html', {
				'error_message': request.session['error'],
				'quiz': Quiz.objects.get(id=quiz_id),
				'user': get_person(request, request.session['id'], request.session['type']),
				'connected': request.session['type'],
				})
			del request.session['error']
		elif 'success' in request.session:
			response = render(request, 'www/professor/question/addqst.html',{
				'quiz': Quiz.objects.get(id=quiz_id),
				'user': get_person(request, request.session['id'], request.session['type']),
				'connected': request.session['type'],
				'success': request.session['success'],
				})
			del request.session['success']
		else:
			response = render(request, 'www/professor/question/addqst.html', {
				'quiz': Quiz.objects.get(id=quiz_id),
				'user': get_person(request, request.session['id'], request.session['type']),
				'connected': request.session['type'],
				})
		user = get_person(request, request.session['id'], request.session['type'])
		if user.type_person != 'professor':
			return HttpResponseRedirect(reverse('www:index'))
	return response

def addqst_confirm(request, quiz_id):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/index.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/index.html')
		return response

	try:
		content = request.POST['question']
	except(KeyError):
		request.session['error'] = "There is something wrong!"
		return HttpResponseRedirect(reverse('www:addqst', kwargs={'quiz_id': quiz_id,}))
	else:
		Question.objects.create(quiz=get_object_or_404(Quiz, id=quiz_id),question_text=content)
		request.session['success'] = 'Add success'
		return HttpResponseRedirect(reverse('www:addqst', kwargs={'quiz_id': quiz_id,}))
		#return HttpResponseRedirect(reverse('www:question', kwargs={'quiz_id': quiz_id,}))

def editqst(request, quiz_id, question_id):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/index.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/index.html')
		return response
	else:
		if 'error' in request.session:
			response = render(request, 'www/professor/question/editqst.html', {
				'error_message': request.session['error'],
				'quiz': Quiz.objects.get(id=quiz_id),
				'qst': Question.objects.get(id=question_id),
				'user': get_person(request, request.session['id'], request.session['type']),
				'connected': request.session['type'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/professor/question/editqst.html', {
				'quiz': Quiz.objects.get(id=quiz_id),
				'qst': Question.objects.get(id=question_id),
				'user': get_person(request, request.session['id'], request.session['type']),
				'connected': request.session['type'],
				})
		user = get_person(request, request.session['id'], request.session['type'])
		if user.type_person != 'professor':
			return HttpResponseRedirect(reverse('www:index'))
	return response

def editqst_confirm(request, quiz_id, question_id):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/index.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/index.html')
		return response
	try:
		qz_id = request.POST['quiz']
		content = request.POST['question']
	except(KeyError):
		request.session['error'] = "There is something wrong!"
		return HttpResponseRedirect(reverse('www:editqst', kwargs={'quiz_id': quiz_id,'question_id': question_id,}))
	else:
		quiz = get_object_or_404(Quiz, id=qz_id)
		question = get_object_or_404(Question, id=question_id)
		Question.objects.filter(id=question_id).update(quiz=quiz,question_text=content)
		request.session['success'] = 'Update success'
		return HttpResponseRedirect(reverse('www:question', kwargs={'quiz_id': quiz_id,}))

def deleteqst(request, quiz_id, question_id):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/index.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/index.html')
		return response

	quiz = get_object_or_404(Quiz, id=quiz_id)
	question = get_object_or_404(Question, id=question_id)
	if quiz.id != question.quiz.id:
		request.session['error'] = ' There is something wrong.'
		return HttpResponseRedirect(reverse('www:question', kwargs={'quiz_id': quiz_id,}))
	request.session['success'] = 'Delete success'
	Question.objects.filter(id=question_id).delete()
	return HttpResponseRedirect(reverse('www:question', kwargs={'quiz_id': quiz_id,}))

def choice(request, question_id):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/index.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/index.html')
		return response

	question = get_object_or_404(Question, id=question_id)
	if 'error' in request.session:
		response = render(request, 'www/professor/choice/choices.html',{
			'error_message': request.session['error'],
			'user': get_person(request, request.session['id'], request.session['type']),
			'quiz': question.quiz,
			'question': question,
			'choice': question.choice_set.all(),
			'connected': request.session['type'],
			})
		del request.session['error']
	elif 'success' in request.session:
		response = render(request, 'www/professor/choice/choices.html',{
			'success': request.session['success'],
			'user': get_person(request, request.session['id'], request.session['type']),
			'quiz': question.quiz,
			'question': question,
			'choice': question.choice_set.all(),
			'connected': request.session['type'],
			})
		del request.session['success']
	else:
		response = render(request, 'www/professor/choice/choices.html',{
			'user': get_person(request, request.session['id'], request.session['type']),
			'quiz': question.quiz,
			'question': question,
			'choice': question.choice_set.all(),
			'connected': request.session['type'],
			})
	return response

def addchoice(request, question_id):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/index.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/index.html')
		return response
	else:
		if 'error' in request.session:
			response = render(request, 'www/professor/choice/addchoice.html', {
				'error_message': request.session['error'],
				'user': get_person(request, request.session['id'], request.session['type']),
				'question': Question.objects.get(id=question_id),
				'connected': request.session['type'],
				})
			del request.session['error']
		elif 'success' in request.session:
			response = render(request, 'www/professor/choice/addchoice.html',{
				'success': request.session['success'],
				'user': get_person(request, request.session['id'], request.session['type']),
				'question': Question.objects.get(id=question_id),
				'connected': request.session['type'],
				})
			del request.session['success']
		else:
			response = render(request, 'www/professor/choice/addchoice.html', {
				'user': get_person(request, request.session['id'], request.session['type']),
				'question': Question.objects.get(id=question_id),
				'connected': request.session['type'],
				})
		user = get_person(request, request.session['id'], request.session['type'])
		if user.type_person != 'professor':
			return HttpResponseRedirect(reverse('www:index'))
	return response

def addchoice_confirm(request, question_id):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/index.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/index.html')
		return response

	try:
		qst = request.POST['question']
		choice = request.POST['choice']
		state = request.POST['state']
	except(KeyError):
		request.session['error'] = "There is something wrong!"
		return HttpResponseRedirect(reverse('www:addchoice', kwargs={'question_id': question_id,}))
	else:
		question = get_object_or_404(Question, id=qst)
		Choice.objects.create(question=question,choice_text=choice,is_true=state)
		request.session['success'] = 'Add success'
		return HttpResponseRedirect(reverse('www:addchoice', kwargs={'question_id': question_id,}))
		#return HttpResponseRedirect(reverse('www:choice', kwargs={'question_id': question_id,}))

def editchoice(request, question_id, choice_id):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/index.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/index.html')
		return response
	else:
		question = get_object_or_404(Question, id=question_id)
		choice = get_object_or_404(Choice, id=choice_id)
		if 'error' in request.session:
			response = render(request, 'www/professor/choice/editchoice.html', {
				'error_message': request.session['error'],
				'user': get_person(request, request.session['id'], request.session['type']),
				'question': choice.question,
				'choice': choice,
				'connected': request.session['type'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/professor/choice/editchoice.html', {
				'user': get_person(request, request.session['id'], request.session['type']),
				'question': choice.question,
				'choice': choice,
				'connected': request.session['type'],
				})
		user = get_person(request, request.session['id'], request.session['type'])
		if user.type_person != 'professor':
			return HttpResponseRedirect(reverse('www:index'))
	return response

def editchoice_confirm(request, question_id, choice_id):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/index.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/index.html')
		return response

	try:
		qst = request.POST['question']
		content = request.POST['choice']
		state = request.POST['state']
	except(KeyError):
		request.session['error'] = "There is something wrong!"
		return HttpResponseRedirect(reverse('www:editchoice', kwargs={'question_id': question_id,'choice_id': choice_id,}))
	else:
		question = get_object_or_404(Question, id=qst)
		choice = get_object_or_404(Choice, id=choice_id)
		Choice.objects.filter(id=choice_id).update(question=question,choice_text=content,is_true=state)
		request.session['success'] = 'Update success'
		return HttpResponseRedirect(reverse('www:choice', kwargs={'question_id': question_id,}))

def deletechoice(request, question_id, choice_id):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/index.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/index.html')
		return response

	question = get_object_or_404(Question, id=question_id)
	choice = get_object_or_404(Choice, id=choice_id)
	if question.id != choice.question.id:
		request.session['error'] = ' There is something wrong.'
		return HttpResponseRedirect(reverse('www:choice', kwargs={'question_id': question_id,}))
	request.session['success'] = 'Delete success'
	Choice.objects.filter(id=choice_id).delete()
	return HttpResponseRedirect(reverse('www:choice', kwargs={'question_id': question_id,}))

###############################################################################################################################
###############################################################################################################################
###############################################################################################################################

def startquiz(request, quiz_id):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/index.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/index.html')
		return response

	request.session['mark'] = 0
	quiz = Quiz.objects.get(id=quiz_id)
	question = quiz.question_set.all()
	#if question.count() == 0:
	if not quiz_iscomplete(quiz_id):
		return render(request, 'www/startquiz.html', {
			'connected': request.session['type'],
			'user': get_person(request, request.session['id'], request.session['type']),
			'quiz': quiz,
			'iscomplete': quiz_iscomplete(quiz_id),
			})

	return render(request, 'www/startquiz.html', {
		'connected': request.session['type'],
		'user': get_person(request, request.session['id'], request.session['type']),
		'quiz': quiz,
		'question': first_question(quiz_id),
		'iscomplete': quiz_iscomplete(quiz_id),
		})

def quizqst(request, quiz_id, question_id):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/index.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/index.html')
		return response

	if 'process' not in request.session:
		request.session['process'] = 0
		request.session['process_pct'] = 0

	quiz = get_object_or_404(Quiz, pk=quiz_id)
	question = quiz.question_set.all()
	qst = get_object_or_404(Question, pk=question_id)
	true_choice = 0
	for c in qst.choice_set.filter(is_true=True):
		true_choice += 1

	for q in question:
		if q.id == qst.id:
			if 'mark' not in request.session:
				request.session['mark'] = 0
			if 'error' in request.session:
				response = render(request, 'www/quizqst.html', {
					'connected': request.session['type'],
					'user': get_person(request, request.session['id'], request.session['type']),
					'quiz': quiz,
					'question': q,
					'mark': request.session['mark'],
					'process': int(request.session['process']),
					'process_pct': int(request.session['process_pct']),
					'true_choice': true_choice,
					'error_message': request.session['error'],
					})
			else:
				response = render(request, 'www/quizqst.html', {
					'connected': request.session['type'],
					'user': get_person(request, request.session['id'], request.session['type']),
					'quiz': quiz,
					'question': q,
					'process': int(request.session['process']),
					'process_pct': int(request.session['process_pct']),
					'true_choice': true_choice,
					'mark': request.session['mark'],
					})

			return response
	raise Http404("Question don't exists")

def checkAnswer(request, quiz_id, question_id):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/index.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/index.html')
		return response

	if 'mark' not in request.session:
		request.session['mark'] = 0
	if 'process' not in request.session:
		request.session['process'] = 0
		request.session['process_pct'] = 0

	user = get_person(request, request.session['id'], request.session['type'])
	question = get_object_or_404(Question, pk=question_id)
	quiz = question.quiz
	nxt_question = next_question(question.id)
	is_true = False


	try:
		choice = question.choice_set.get(pk=request.POST['choice'])
	except(KeyError, Choice.DoesNotExist):
		request.session['error'] = "You didn't select a valid choice."
		return HttpResponseRedirect(reverse('www:quizqst', args=(quiz.id, nxt_question.id,)))
	else:

		if choice.is_true:
			request.session['mark'] += 1
			is_true = True

		try:
			ar = Archive.objects.get(choice__question=question, person=user)
		except (Archive.DoesNotExist):
			Archive.objects.create(person=user, choice=choice, is_true=is_true)
		else:
			Archive.objects.filter(id=ar.id).update(is_true=is_true)

		nb_qst = quiz.question_set.count()
		request.session['process'] += 1
		process = ( float(request.session['process']) / nb_qst )*100
		request.session['process_pct'] = process

		qst = last_question(quiz.id)
		if question.id == qst.id:
			return HttpResponseRedirect(reverse('www:result', kwargs={'quiz_id': quiz.id,}))
		return HttpResponseRedirect(reverse('www:quizqst', args=(quiz.id, nxt_question.id,)))

def checkboxAnswer(request, quiz_id, question_id):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/index.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/index.html')
		return response

	if 'mark' not in request.session:
		request.session['mark'] = 0
	if 'process' not in request.session:
		request.session['process'] = 0
		request.session['process_pct'] = 0

	user = get_person(request, request.session['id'], request.session['type'])
	question = get_object_or_404(Question, pk=question_id)
	quiz = question.quiz
	nxt_question = next_question(question.id)
	is_true = False
	check = True


	try:
		submited = request.POST.getlist('choice[]')
	except(KeyError):
		request.session['error'] = "You didn't select a valid choice."
		return HttpResponseRedirect(reverse('www:quizqst', args=(quiz.id, nxt_question.id,)))
	else:
		counter = 0
		for x in submited:
			counter += 1
		if question.choice_set.filter(is_true=True).count() != counter:
			check = False
		for sub in submited:
			choice = question.choice_set.get(pk=sub)
			if not choice.is_true:
				check = False
		if check:
			request.session['mark'] += 1
			is_true = True

		try:
			ar = Archive.objects.get(choice__question=question, person=user)
		except (Archive.DoesNotExist):
			Archive.objects.create(person=user, choice=choice, is_true=is_true)
		else:
			Archive.objects.filter(id=ar.id).update(is_true=is_true)

		nb_qst = quiz.question_set.count()
		request.session['process'] += 1
		process = ( float(request.session['process']) / nb_qst )*100
		request.session['process_pct'] = process

		qst = last_question(quiz.id)
		if question.id == qst.id:
			return HttpResponseRedirect(reverse('www:result', kwargs={'quiz_id': quiz.id,}))
		return HttpResponseRedirect(reverse('www:quizqst', args=(quiz.id, nxt_question.id,)))

def result(request, quiz_id):
	if not_connected(request.session):
		if 'error' in request.session:
			response = render(request, 'www/index.html', {
				'error_message': request.session['error'],
				})
			del request.session['error']
		else:
			response = render(request, 'www/index.html')
		return response
	if 'process' in request.session:
		del request.session['process']
		del request.session['process_pct']

	user = get_person(request, request.session['id'], request.session['type'])
	quiz = get_object_or_404(Quiz, id=quiz_id)
	nb_qst = quiz.question_set.count()
	archive = Archive.objects.filter(person=user, choice__question__quiz=quiz).order_by('id')

	mark = 0
	for ar in archive:
		if ar.is_true:
			mark += 1

	true_qst = mark
	nb_qst = quiz.question_set.count()
	mark = ( float(mark) / nb_qst)*100

	question = first_question(quiz.id)
	return render(request, 'www/result.html', {
		'quiz': quiz,
		'connected': request.session['type'],
		'mark': int(mark),
		'archive': archive,
		'question': question,
		'true_qst': true_qst,
		'user': get_person(request, request.session['id'], request.session['type']),
		})
