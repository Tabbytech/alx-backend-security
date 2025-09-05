from django.http import HttpResponse
from django_ratelimit.decorators import ratelimit
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from functools import wraps

from .utils import user_or_ip


def dynamic_ratelimit(view_func):
    """Apply different rate limits for authenticated and anonymous users."""
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if request.user.is_authenticated:
            decorator = ratelimit(key=user_or_ip, rate="10/m", block=True)
        else:
            decorator = ratelimit(key=user_or_ip, rate="5/m", block=True)
        return decorator(view_func)(request, *args, **kwargs)
    return _wrapped_view


@csrf_exempt
@dynamic_ratelimit
def login_view(request):
    return HttpResponse("Coded Login successful (Real view)")
