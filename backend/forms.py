from allauth.socialaccount.forms import SignupForm
class MyCustomSignupForm(SignupForm):

    def save(self, request):
        user = super(MyCustomSignupForm, self).save(request)
        return user