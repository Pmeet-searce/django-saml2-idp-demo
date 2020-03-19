# Generated by Django 2.2 on 2020-03-19 11:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('djangosaml2idp_app', '0002_auto_20200313_1221'),
    ]

    operations = [
        migrations.CreateModel(
            name='ServiceProvider',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('dt_created', models.DateTimeField(auto_now_add=True)),
                ('dt_updated', models.DateTimeField(auto_now=True, null=True)),
                ('entity_id', models.CharField(max_length=256, unique=True)),
                ('description', models.TextField(blank=True)),
                ('metadata_expiration_dt', models.DateTimeField()),
                ('remote_metadata_url', models.CharField(blank=True, max_length=512)),
                ('local_metadata', models.TextField(blank=True)),
                ('active', models.BooleanField(default=True)),
                ('_processor', models.CharField(default='djangosaml2idp_app.processors.BaseProcessor', max_length=256)),
                ('_attribute_mapping', models.TextField(default='{"email": "email", "first_name": "first_name", "last_name": "last_name", "is_staff": "is_staff", "is_superuser": "is_superuser"}')),
                ('_nameid_field', models.CharField(blank=True, max_length=64)),
                ('_sign_response', models.BooleanField(blank=True, null=True)),
                ('_sign_assertion', models.BooleanField(blank=True, null=True)),
                ('_signing_algorithm', models.CharField(blank=True, choices=[('http://www.w3.org/2000/09/xmldsig#rsa-sha1', 'SIG_RSA_SHA1'), ('http://www.w3.org/2001/04/xmldsig-more#rsa-sha224', 'SIG_RSA_SHA224'), ('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256', 'SIG_RSA_SHA256'), ('http://www.w3.org/2001/04/xmldsig-more#rsa-sha384', 'SIG_RSA_SHA384'), ('http://www.w3.org/2001/04/xmldsig-more#rsa-sha512', 'SIG_RSA_SHA512')], max_length=256, null=True)),
                ('_digest_algorithm', models.CharField(blank=True, choices=[('http://www.w3.org/2000/09/xmldsig#sha1', 'DIGEST_SHA1'), ('http://www.w3.org/2001/04/xmldsig-more#sha224', 'DIGEST_SHA224'), ('http://www.w3.org/2001/04/xmlenc#sha256', 'DIGEST_SHA256'), ('http://www.w3.org/2001/04/xmldsig-more#sha384', 'DIGEST_SHA384'), ('http://www.w3.org/2001/04/xmlenc#sha512', 'DIGEST_SHA512'), ('http://www.w3.org/2001/04/xmlenc#ripemd160', 'DIGEST_RIPEMD160')], max_length=256, null=True)),
                ('_encrypt_saml_responses', models.BooleanField(null=True)),
            ],
            options={
                'verbose_name': 'Service Provider',
                'verbose_name_plural': 'Service Providers',
            },
        ),
        migrations.DeleteModel(
            name='User',
        ),
        migrations.AddIndex(
            model_name='serviceprovider',
            index=models.Index(fields=['entity_id'], name='djangosaml2_entity__49d919_idx'),
        ),
    ]
