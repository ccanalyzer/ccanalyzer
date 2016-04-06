import re
import json

from django.contrib import messages
from django.shortcuts import render, redirect
from django.http import  HttpResponse, Http404
from django.core.files.uploadedfile import TemporaryUploadedFile

from . import apps
from . import forms
from . import models


def index(request):
    """ lists any *.{cfg,conf,config} file at configured repository path """
    repository_config_files = models.Repository.list(apps.Config.repo_path)
    return render(request, 'analyzer/index.html', {
        'repository_config_files': repository_config_files,
        'audit_upload_form': forms.AuditUploadForm(),
    })

def search(request):
    """ searches a regex in repository, returns a json object """
    query_regex = request.GET.get('query')
    data = { 'success': True, 'results': [] }
    if len(query_regex) > 0:
        try:
            for result in models.Repository.find(apps.Config.repo_path, query_regex):
                data['results'].append({ # need some representation
                    'file'   : result['file'].to_json(),
                    'matches': result['file_matches']
                })
        except re.error as e:
            data = { 'success': False, 'message': 'verify your Regular Expression (%s)' % e.message }
        except Exception:
            data = { 'success': False, 'message': 'unknown error, see error_log!!!' }
    else:
        data = {'success': False, 'message': 'Please specify a Regular Expression'}

    response = HttpResponse(content_type='application/json')
    response.write(json.dumps(data, ensure_ascii=False))
    return response

def download(request):
    """ serves a download'able cisco config, if found. 404 otherwise """
    config_file_name = request.GET.get('config') or ''
    config_file = models.Repository.load(apps.Config.repo_path, config_file_name)
    if not config_file: # couldn't find/load a file by the requested param? yawn...
        raise Http404

    response = HttpResponse(content_type='text/plain') # not aware of any cisco MIME
    response['Content-Disposition'] = 'attachment; filename="%s"' % config_file_name
    response.write(config_file.contents) # outputs anything on that file
    return response


def audit(request):
    """ performs some basic analysis on a specified cisco configuration file """
    config_file_name = request.GET.get('config') or ''
    config_file = models.Repository.load(apps.Config.repo_path, config_file_name)
    if not config_file:  # couldn't find/load a file by the requested param? yawn...
        raise Http404

    # XXX: won't wrap it inside try/except as i rely on django's dbg
    config_audit = models.Audit(config_file.path, config_file.name)
    return render(request, 'analyzer/audit.html', {
        'report': config_audit.do_report(),
    })


def audit_upload(request):
    """ handles an uploaded cisco configuration file, analyzes it, and deletes it """
    form = forms.AuditUploadForm(request.POST, request.FILES)
    if not form.is_valid():
        try:
            json_errors = json.loads(form.errors.as_json())
            if 'config_file' in json_errors:
                messages.error(request, "Could not parse Uploaded File (reason: %s)"
                               % json_errors['config_file'][0]['message'])
                return redirect('index')
        except ValueError: pass

        # fallback as this should not happen unless KeyError is raised somehow
        messages.error(request, "Could not parse Uploaded File")
        return redirect('index')

    config_file = request.FILES['config_file']
    if not type(config_file) == TemporaryUploadedFile: # better working with real paths than in-memory stuff
        messages.error(request, "Enable TemporaryFileUploadHandler in ccanalyzer/settings.py!")
        return redirect('index')

    config_audit = models.Audit(config_file.temporary_file_path(), config_file.name)

    # XXX: won't wrap it inside try/except as i rely on django's dbg
    return render(request, 'analyzer/audit.html', {
        'report': config_audit.do_report(),
    })
