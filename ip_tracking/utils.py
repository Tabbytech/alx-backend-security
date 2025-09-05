def user_or_ip(group, request):
    if request.user.is_authenticated:
        return str(request.user.id)
    ip = request.META.get("REMOTE_ADDR")
    if not ip:  # fallback for proxy setups
        ip = request.META.get("HTTP_X_FORWARDED_FOR", "").split(",")[0].strip()
    return ip
