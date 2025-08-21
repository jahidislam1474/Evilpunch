# Generated manually for adding is_cache_enabled field to Phishlet model

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0013_alter_session_options_session_telegram_message_id_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='phishlet',
            name='is_cache_enabled',
            field=models.BooleanField(
                default=True,
                help_text='Whether static file caching is enabled for this phishlet'
            ),
        ),
    ]
