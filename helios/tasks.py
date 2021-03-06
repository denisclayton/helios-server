# -*- coding: iso-8859-1 -*-
"""
Celery queued tasks for Helios

2010-08-01
ben@adida.net
"""

from celery.decorators import task

from models import *
from view_utils import render_template_raw
import signals

import copy

from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from django.utils.translation import activate


@task()
def cast_vote_verify_and_store(cast_vote_id, status_update_message=None, **kwargs):
    activate(settings.LANGUAGE_CODE)
    cast_vote = CastVote.objects.get(id = cast_vote_id)
    result = cast_vote.verify_and_store()

    voter = cast_vote.voter
    election = voter.election
    user = voter.user

    if result:
        # send the signal
        signals.vote_cast.send(sender=election, election=election, user=user, voter=voter, cast_vote=cast_vote)
        
        if status_update_message and user.can_update_status():
            from views import get_election_url

            user.update_status(status_update_message)
    else:
        logger = cast_vote_verify_and_store.get_logger(**kwargs)
        logger.error("Failed to verify and store %d" % cast_vote_id)
    
@task()
def voters_email(election_id, subject_template, body_template, extra_vars={},
                 voter_constraints_include=None, voter_constraints_exclude=None):
    """
    voter_constraints_include are conditions on including voters
    voter_constraints_exclude are conditions on excluding voters
    """
    activate(settings.LANGUAGE_CODE)
    election = Election.objects.get(id = election_id)

    # select the right list of voters
    voters = election.voter_set.all()
    if voter_constraints_include:
        voters = voters.filter(**voter_constraints_include)
    if voter_constraints_exclude:
        voters = voters.exclude(**voter_constraints_exclude)

    for voter in voters:
        single_voter_email.delay(voter.uuid, subject_template, body_template, extra_vars)            

@task()
def voters_notify(election_id, notification_template, extra_vars={}):
    activate(settings.LANGUAGE_CODE)
    election = Election.objects.get(id = election_id)
    for voter in election.voter_set.all():
        single_voter_notify.delay(voter.uuid, notification_template, extra_vars)

@task()
def single_voter_email(voter_uuid, subject_template, body_template, extra_vars={}):
    activate(settings.LANGUAGE_CODE)
    voter = Voter.objects.get(uuid = voter_uuid)

    the_vars = copy.copy(extra_vars)
    the_vars.update({'voter' : voter})

    subject = render_template_raw(None, subject_template, the_vars)
    body = render_template_raw(None, body_template, the_vars)

    voter.user.send_message(subject, body)

@task()
def single_voter_notify(voter_uuid, notification_template, extra_vars={}):
    activate(settings.LANGUAGE_CODE)
    voter = Voter.objects.get(uuid = voter_uuid)

    the_vars = copy.copy(extra_vars)
    the_vars.update({'voter' : voter})

    notification = render_template_raw(None, notification_template, the_vars)

    voter.user.send_notification(notification)

@task()
def election_compute_tally(election_id):
    activate(settings.LANGUAGE_CODE)
    election = Election.objects.get(id = election_id)
    election.compute_tally()

    if not settings.RODAPE_EMAILS_TASKS:
      str_rodape = " "
    else:
      str_rodape = settings.RODAPE_EMAILS_TASKS

    election_notify_admin.delay(election_id = election_id,
                                subject = _("encrypted tally computed"),
                                body = _("The encrypted tally for election %s has been computed. %s") % (election.name, str_rodape))

    if election.has_helios_trustee():
        tally_helios_decrypt.delay(election_id = election.id)

@task()
def tally_helios_decrypt(election_id):
    activate(settings.LANGUAGE_CODE)
    election = Election.objects.get(id = election_id)
    election.helios_trustee_decrypt()

    if not settings.RODAPE_EMAILS_TASKS:
      str_rodape = " "
    else:
      str_rodape = settings.RODAPE_EMAILS_TASKS

    election_notify_admin.delay(election_id = election_id,
                                subject = _('Helios Decrypt'),
                                body = _("Helios has decrypted its portion of the tally for election %s. %s") % (election.name, str_rodape))

@task()
def voter_file_process(voter_file_id):
    activate(settings.LANGUAGE_CODE)
    voter_file = VoterFile.objects.get(id = voter_file_id)
    voter_file.process()

    if not settings.RODAPE_EMAILS_TASKS:
      str_rodape = " "
    else:
      str_rodape = settings.RODAPE_EMAILS_TASKS

    election_notify_admin.delay(election_id = voter_file.election.id, 
                                subject = _('voter file processed'),
                                body = _("Your voter file upload for election %s has been processed. %s voters have been created. %s") % (voter_file.election.name, voter_file.num_voters, str_rodape))

@task()
def election_notify_admin(election_id, subject, body):
    activate(settings.LANGUAGE_CODE)
    election = Election.objects.get(id = election_id)
    election.admin.send_message(subject, body)
