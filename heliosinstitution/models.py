import datetime


from django.db import models
from django.db.models import Max, Count
from django.utils.translation import ugettext as _
from django.contrib.auth.models import User


class Institution(models.Model):
  
    name = models.CharField(max_length=250)
    short_name = models.CharField(max_length=100, blank=True)
    main_phone = models.CharField(max_length=25)
    sec_phone = models.CharField(max_length=25, blank=True)
    address = models.TextField()
    idp_address = models.URLField(null=True, blank=True)
  
    class Meta:
        permissions = (
            ("delegate_institution_mngt", _("Can delegate institution management tasks")),
            ("revoke_institution_mngt", _("Can revoke institution management tasks")),
            ("delegate_election_mngt", _("Can delegate election management tasks")),
            ("revoke_election_mngt", _("Can revoke election management tasks")),
    )

    def __unicode__(self):
        return self.name
  
    @property
    def institution_users(self):
        users = []
        for user in self.institutionuserprofile_set.all():
            users.append({
                'pk': user.pk,
                'helios_user': user.helios_user,
                'email': user.email,
                'role': user.institution_role,
                'active': user.active,
                'expires_at': user.expires_at,
            })
        return users

    @property
    def elections(self):
        from helios.models import Election
        elections = []
        for election in Election.objects.filter(admin__in=[
            user for user in self.institutionuserprofile_set.all()]).order_by('-created_at'):
            elections.append({
                'pk': election.pk,
                'uuid': election.uuid,
                'name': election.name,
                'admin': election.admin.pretty_name,
                'voters': election.num_voters,
                'cast_votes': election.num_cast_votes,
            })

        return elections

    @property
    def recently_cast_votes(self):
        from helios.models import Election
        recently_cast_votes = []
        for election in Election.objects.filter(
            voter__castvote__cast_at__gt= datetime.datetime.utcnow() - datetime.timedelta(days=1),
                admin__in=[user for user in self.institutionuserprofile_set.all()]).annotate(
                    last_cast_vote = Max('voter__castvote__cast_at'),
                        num_recent_cast_votes = Count('voter__castvote')).order_by('-last_cast_vote'):
          recently_cast_votes.append({
            'uuid': election.uuid,
            'name': election.name,
            'last_cast_vote':  election.last_cast_vote,
            'num_recent_cast_vote': election.num_recent_cast_votes,
          })

        return recently_cast_votes


class InstitutionUserProfile(models.Model):

    helios_user = models.ForeignKey('helios_auth.User', blank=True, default=None, null=True)
    django_user = models.ForeignKey(User, unique=True)
    institution = models.ForeignKey("heliosinstitution.Institution")
    email = models.EmailField(max_length=254)
    expires_at = models.DateTimeField(auto_now_add=False, default=None, null=True, blank=True)
    active = models.BooleanField(default=False)
  
    def __unicode__(self):
        return self.helios_user.name if self.helios_user is not None else self.email
        

    @property
    def is_institution_admin(self):
        return self.django_user.groups.filter(name='Institution Admin').exists()

    @property
    def institution_role(self):
        #TODO: check for user group instead
        if self.is_institution_admin:
            return _("Institution Admin")
        if self.django_user.groups.filter(name="Election Admin").exists():
            return _("Election Admin")
        return _("Undefined")

    @property
    def institution_user_voter_attributes(self):
        '''
        Returns attributes to be used when constraining election voters.
        These attributes are institution's election managers specific
        '''
        from django.conf import settings
        attributes = self.helios_user.info['attributes']

        if settings.USE_ELECTION_MANAGER_ATTRIBUTES:
            for attribute in settings.ELECTION_MANAGER_ATTRIBUTES:
                try:
                    attributes.pop(attribute)
                except KeyError:
                    pass

        return attributes