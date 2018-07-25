import datetime

from django.utils import timezone
from django.db import models
from django.utils.encoding import python_2_unicode_compatible


@python_2_unicode_compatible
class Person(models.Model):
	cin = models.CharField(max_length=100)
	username = models.CharField(max_length=250)
	password = models.CharField(max_length=1000)
	email = models.CharField(max_length=1000)
	is_valid = models.BooleanField(default=False)

	def __str__(self):
		return self.username + ' - ' + self.email

@python_2_unicode_compatible
class User(Person):
	type_person = models.CharField(default='user', max_length=250)

	def __str__(self):
		return super(Person, self).__str__()

@python_2_unicode_compatible
class Professor(User):
	def __str__(self):
		return super(User, self).__str__()
Professor._meta.get_field('type_person').default = 'professor'

@python_2_unicode_compatible
class Admin(Person):
	type_person = models.CharField(default='admin', max_length=250)

	def __str__(self):
		return super(Person, self).__str__()

@python_2_unicode_compatible
class Quiz(models.Model):
	quiz_prof = models.ForeignKey(Professor, on_delete=models.CASCADE)
	quiz_subject = models.CharField(max_length=300)
	pub_date = models.DateTimeField(default=timezone.now)

	def __str__(self):
		return self.quiz_subject + ' - ' + self.quiz_prof.username

@python_2_unicode_compatible
class Question(models.Model):
	quiz = models.ForeignKey(Quiz, on_delete=models.CASCADE)
	question_text = models.CharField(max_length=200)

	def __str__(self):
		return self.question_text

@python_2_unicode_compatible
class Choice(models.Model):
	question = models.ForeignKey(Question, on_delete=models.CASCADE)
	choice_text = models.CharField(max_length=200)
	is_true = models.BooleanField(default=False)

	def __str__(self):
		return self.choice_text

@python_2_unicode_compatible
class Archive(models.Model):
	choice = models.ForeignKey(Choice, on_delete=models.CASCADE)
	person = models.ForeignKey(User, on_delete=models.CASCADE)
	is_true = models.BooleanField(default=False)

	class Meta:
		unique_together = ('choice', 'person')

	def __str__(self):
		return self.person + ' : ' + self.choice + ' - ' + self.is_true