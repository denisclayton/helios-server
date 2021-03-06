"""
Glue some events together 
"""

from django.conf import settings
from django.core.urlresolvers import reverse
from django.conf import settings
from django.utils.translation import ugettext as _

import helios.views, helios.signals

import views

def vote_cast_send_message(user, voter, election, cast_vote, **kwargs):
  ## FIXME: this doesn't work for voters that are not also users
  # prepare the message
  subject = _("[vote cast] - %(election_name)s") % {'election_name' : election.name}

  body = _('You have successfully cast a vote in\n\n%(election_name)s\n') % {'election_name' : election.name}

  body += _('Your ballot is archived at:\n\n%(cast_url)s\n') % {'cast_url' : helios.views.get_castvote_url(cast_vote)}
  
  body += '\n\n'

  if election.use_voter_aliases:
    body += _('\nThis election uses voter aliases to protect your privacy.'
'Your voter alias is :\n\n%(voter_alias)s') % {'voter_alias' : voter.alias}

  body += """

--
%s
""" % settings.SITE_TITLE  
  
  # send it via the notification system associated with the auth system
  user.send_message(subject, body)

helios.signals.vote_cast.connect(vote_cast_send_message)

def election_tallied(election, **kwargs):
  pass

helios.signals.election_tallied.connect(election_tallied)
