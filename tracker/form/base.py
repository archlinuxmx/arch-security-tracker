from flask_wtf import FlaskForm
from wtforms import PasswordField


class BaseForm(FlaskForm):
    class Meta:
        def bind_field(self, form, unbound_field, options):
            filters = list(unbound_field.kwargs.get('filters', []))
            if not issubclass(unbound_field.field_class, PasswordField):
                filters.append(strip_filter)
            return unbound_field.bind(form=form, filters=filters, **options)


def strip_filter(value):
    if not value or not hasattr(value, 'strip'):
        return value
    return value.strip()
