# Generated by Django 5.1.4 on 2024-12-10 18:30

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('patient_app', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='communication',
            name='sender',
            field=models.CharField(max_length=100),
        ),
    ]
