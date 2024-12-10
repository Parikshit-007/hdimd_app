# Generated by Django 5.1.4 on 2024-12-10 20:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('patient_app', '0002_alter_communication_sender'),
    ]

    operations = [
        migrations.CreateModel(
            name='Appointment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('doctor_name', models.CharField(max_length=255)),
                ('patient_name', models.CharField(max_length=255)),
                ('appointment_date', models.DateField()),
                ('time_slot', models.DateTimeField()),
                ('status', models.CharField(choices=[('pending', 'pending'), ('confirmed', 'confirmed')], max_length=10)),
                ('total_visits', models.IntegerField()),
            ],
        ),
        migrations.CreateModel(
            name='EHR',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('upload_type', models.CharField(choices=[('text', 'Text'), ('file', 'File')], max_length=10)),
                ('title', models.CharField(blank=True, max_length=255, null=True)),
                ('description', models.TextField(blank=True, null=True)),
                ('file', models.FileField(blank=True, null=True, upload_to='uploads/')),
                ('encrypted_data', models.TextField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]