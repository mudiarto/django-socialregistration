from django.dispatch import Signal


# A new facebook user has registered.
socialregistrationuser_created = Signal(providing_args=["user", "profile", "request"])

