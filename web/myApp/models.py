from django.db import models

# Create your models here.
class cfg(models.Model):
	PROTO_CHOICES = ( ('BGP', 'BGP'), ('SSL', 'SSL'),)
	serverIP = models.GenericIPAddressField()
	custID = models.IntegerField()
	protocol = models.CharField(
				max_length=3, choices=PROTO_CHOICES, default='BGP',)
	slug = models.SlugField(unique=True)
