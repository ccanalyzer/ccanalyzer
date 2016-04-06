import magic

from django import forms

class AuditUploadForm(forms.Form):
    config_file = forms.FileField()
    def clean_file(self):
        """ config_file MIME-type must be text/plain """
        config_file = self.cleaned_data.get("config_file", False)
        config_file_type = magic.from_buffer(config_file.read(), mime=True)
        if not 'text/plain' in config_file_type:
            raise forms.ValidationError("must be text/plain, got %s instead" % config_file_type)

        return config_file