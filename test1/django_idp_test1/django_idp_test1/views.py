from django.conf import settings
from django.views.generic import TemplateView

class IndexView(TemplateView):
    template_name="index.html"
    
    def get_context_data(self, **kwargs):
        context = super(IndexView,self).get_context_data(**kwargs)
        context.update({
            "logout_url":settings.LOGOUT_URL,
            "login_url":settings.LOGIN_URL,
        })
        if self.request.user.is_authenticated:
            context.update({
                "authenticated":"congratulations."
            })
    
        return context
    