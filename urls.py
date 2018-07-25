from django.conf.urls import url
from . import views

app_name = 'www'

urlpatterns = [
    url(r'^$', views.index, name="index"),
    url(r'^quiz/$', views.quiz, name="quiz"),
    url(r'^signin/$', views.login_page, name="login_page"),
    url(r'^login/$', views.login, name="login"),
    url(r'^signup/$', views.register_page, name="register_page"),
    url(r'^register/$', views.register, name="register"),
    url(r'^logout/$', views.logout, name="logout"),
    ####################################################
    ####################################################
    ####################################################
    url(r'^admin/$', views.indexAdmin, name="indexAdmin"),
    url(r'^admin/add/$', views.add, name='add'),
    url(r'^admin/add/validation/$', views.add_user, name='add_user'),
    url(r'^admin/edit/(?P<type_person>[A-Za-z]+)/(?P<user_id>[0-9]+)/$', views.edit, name='edit'),
    url(r'^admin/add/(?P<type_person>[A-Za-z]+)/(?P<user_id>[0-9]+)/validation/$', views.edit_user, name='edit_user'),
    url(r'^admin/delete/(?P<user_id>[0-9]+)/$', views.delete, name='delete'),
    url(r'^admin/unlock/(?P<user_id>[0-9]+)/$', views.unlock, name='unlock'),
    ####################################################
    ####################################################
    ####################################################
    url(r'^professor/$', views.indexProf, name="indexProf"),
    url(r'^professor/myquizs/$', views.myquizs, name="myquizs"),
    url(r'^professor/quiz/add/$', views.addquiz, name='addquiz'),
    url(r'^professor/quiz/add/validation/$', views.addquiz_confirm, name='addquiz_confirm'),
    url(r'^professor/quiz/edit/(?P<quiz_id>[0-9]+)/$', views.editquiz, name='editquiz'),
    url(r'^professor/quiz/edit/(?P<quiz_id>[0-9]+)/validation/$', views.editquiz_confirm, name='editquiz_confirm'),
    url(r'^professor/quiz/delete/(?P<quiz_id>[0-9]+)/$', views.deletequiz, name='deletequiz'),
    url(r'^professor/quiz/(?P<quiz_id>[0-9]+)/question/$', views.question, name='question'),
    url(r'^professor/quiz/(?P<quiz_id>[0-9]+)/question/add/$', views.addqst, name='addqst'),
    url(r'^professor/quiz/(?P<quiz_id>[0-9]+)/question/add/validation/$', views.addqst_confirm, name='addqst_confirm'),
    url(r'^professor/quiz/(?P<quiz_id>[0-9]+)/question/(?P<question_id>[0-9]+)/edit/$', views.editqst, name='editqst'),
    url(r'^professor/quiz/(?P<quiz_id>[0-9]+)/question/(?P<question_id>[0-9]+)/edit/validation/$', views.editqst_confirm, name='editqst_confirm'),
    url(r'^professor/quiz/(?P<quiz_id>[0-9]+)/question/(?P<question_id>[0-9]+)/delete/$', views.deleteqst, name='deleteqst'),
    url(r'^professor/question/(?P<question_id>[0-9]+)/choice/$', views.choice, name='choice'),
    url(r'^professor/question/(?P<question_id>[0-9]+)/choice/add/$', views.addchoice, name='addchoice'),
    url(r'^professor/question/(?P<question_id>[0-9]+)/choice/add/validation/$', views.addchoice_confirm, name='addchoice_confirm'),
    url(r'^professor/question/(?P<question_id>[0-9]+)/choice/(?P<choice_id>[0-9]+)/edit/$', views.editchoice, name='editchoice'),
    url(r'^professor/question/(?P<question_id>[0-9]+)/choice/(?P<choice_id>[0-9]+)/edit/validation/$', views.editchoice_confirm, name='editchoice_confirm'),
    url(r'^professor/question/(?P<question_id>[0-9]+)/choice/(?P<choice_id>[0-9]+)/delete/$', views.deletechoice, name='deletechoice'),
    ####################################################
    ####################################################
    ####################################################
    url(r'^quiz/(?P<quiz_id>[0-9]+)/start/$', views.startquiz, name='startquiz'),
    url(r'^quiz/(?P<quiz_id>[0-9]+)/(?P<question_id>[0-9]+)/start/$', views.quizqst, name='quizqst'),
    url(r'^quiz/(?P<quiz_id>[0-9]+)/(?P<question_id>[0-9]+)/check/$', views.checkAnswer, name='check'),
    url(r'^quiz/(?P<quiz_id>[0-9]+)/(?P<question_id>[0-9]+)/checkbox/$', views.checkboxAnswer, name='checkbox'),
    url(r'^quiz/(?P<quiz_id>[0-9]+)/result/$', views.result, name='result'),
]
