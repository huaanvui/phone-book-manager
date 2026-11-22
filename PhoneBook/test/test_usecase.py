"""Service tests mapped to UC01-UC24; python -m unittest discover -s tests -v"""
import csv
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from phonebook.database import Database
from phonebook.models import User, Contact, Group, Session as LoginSession
from phonebook.services import (AppError, ValidationError, AuthService, ContactService,
                                GroupService, ImportExportService, EmailService)


class FakeMailer:
    def __init__(self):self.messages=[]
    def send_reset_code(self,email,code):self.messages.append((email,code))


class UseCaseTests(unittest.TestCase):
    def setUp(self):
        self.db=Database('sqlite:///:memory:')
        self.db.initialize()
        self.mailer=FakeMailer()
        self.auth=AuthService(self.db,mailer=self.mailer)
        self.contacts=ContactService(self.db)
        self.groups=GroupService(self.db)
        self.io=ImportExportService(self.db,self.contacts)
        self.uid=self.auth.register('Alex Nguyen','alex@example.com','strongpass123','strongpass123')
        self.other=self.auth.register('Other User','other@example.com','otherpassword','otherpassword')
        self.token,self.logged_id,_=self.auth.login('alex@example.com','strongpass123')
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.db.dispose)

    def make_contact(self,name='Alice',phone='0901234567',email='alice@example.com',**kwargs):
        return self.contacts.create(self.uid,name=name,phone=phone,email=email,**kwargs)

    def test_uc01_register(self):
        with self.assertRaises(ValidationError):self.auth.register('','bad','123','456')
        with self.assertRaises(AppError):self.auth.register('Alex','alex@example.com','strongpass123','strongpass123')
        with self.db.session() as d:
            u=d.get(User,self.uid)
            self.assertNotEqual('strongpass123',u.password_hash)
            self.assertIn('pbkdf2_',u.password_hash)

    def test_uc02_login_and_session(self):
        self.assertEqual(self.logged_id,self.uid)
        self.assertEqual(self.auth.get_user(self.token).id,self.uid)
        with self.assertRaises(AppError):self.auth.login('alex@example.com','notmypassword')
        with self.db.session() as d:
            self.assertEqual(d.get(User,self.uid).failed_logins,1)

    def test_uc03_logout(self):
        self.auth.logout(self.token)
        self.assertIsNone(self.auth.get_user(self.token))
        self.auth.logout(self.token)

    def test_uc04_email_verified_reset(self):
        self.auth.request_reset('alex@example.com')
        self.assertEqual(len(self.mailer.messages),1)
        code=self.mailer.messages[-1][1]
        with self.assertRaises(AppError):self.auth.resetPassword('alex@example.com','00000000','newpassword123','newpassword123')
        self.assertTrue(self.auth.resetPassword('alex@example.com',code,'newpassword123','newpassword123'))
        self.assertIsNone(self.auth.get_user(self.token))
        with self.assertRaises(AppError):self.auth.login('alex@example.com','strongpass123')
        self.assertEqual(self.auth.login('alex@example.com','newpassword123')[1],self.uid)
        with self.assertRaises(AppError):self.auth.resetPassword('alex@example.com',code,'thirdpassword123','thirdpassword123')

    def test_uc04_email_nonexistent_no_disclosure(self):
        self.auth.request_reset('absent@example.com')
        self.assertFalse(self.mailer.messages)

    def test_uc05_add_and_uc22_validate(self):
        cid=self.make_contact()
        c=self.contacts.get(self.uid,cid)
        self.assertFalse(c.is_favorite);self.assertFalse(c.is_deleted)
        with self.assertRaises(ValidationError) as ctx:
            self.contacts.create(self.uid,name='',phone='not phone',email='wrong')
        self.assertIn('Name',ctx.exception.errors)
        self.assertIn('Phone',ctx.exception.errors)
        self.assertIn('Email',ctx.exception.errors)

    def test_uc06_view_contact_and_cross_account(self):
        cid=self.make_contact()
        self.assertEqual(self.contacts.get(self.uid,cid).name,'Alice')
        with self.assertRaises(AppError):self.contacts.get(self.other,cid)
        self.assertEqual(len(self.contacts.list_contacts(self.other)),0)

    def test_uc07_edit_and_rollback(self):
        cid=self.make_contact()
        self.contacts.update(self.uid,cid,name='Alice Chen',phone='0987654321',email='alice2@example.com')
        self.assertEqual(self.contacts.get(self.uid,cid).name,'Alice Chen')
        with self.assertRaises(ValidationError):
            self.contacts.update(self.uid,cid,name='',phone='bad',email='x')
        self.assertEqual(self.contacts.get(self.uid,cid).name,'Alice Chen')

    def test_uc08_delete_uc23_confirm(self):
        cid=self.make_contact()
        with self.assertRaises(AppError):self.contacts.delete(self.uid,cid)
        self.assertEqual(len(self.contacts.list_contacts(self.uid)),1)
        self.contacts.delete(self.uid,cid,confirmed=True)
        self.assertFalse(self.contacts.list_contacts(self.uid))
        self.assertEqual(self.contacts.list_contacts(self.uid,trash=True)[0].id,cid)
        with self.assertRaises(AppError):self.contacts.delete(self.uid,cid,confirmed=True)

    def test_uc09_favorite_toggle(self):
        cid=self.make_contact()
        self.assertTrue(self.contacts.toggle_favorite(self.uid,cid))
        self.assertEqual(len(self.contacts.filter(self.uid,favorites=True)),1)
        self.assertFalse(self.contacts.toggle_favorite(self.uid,cid))
        self.assertFalse(self.contacts.filter(self.uid,favorites=True))

    def test_uc10_restore_with_groups(self):
        gid=self.groups.create(self.uid,'Family')
        cid=self.make_contact(group_ids=[gid])
        self.contacts.delete(self.uid,cid,confirmed=True)
        self.contacts.restore(self.uid,cid)
        self.assertEqual([g.id for g in self.contacts.get(self.uid,cid).groups],[gid])
        self.assertFalse(self.contacts.list_contacts(self.uid,trash=True))

    def test_uc11_search_case_insensitive_and_partial(self):
        self.make_contact('Ánh Nguyen',email='anha@example.com')
        self.make_contact('Bella',phone='0922554433',email='b@example.com')
        self.assertEqual(len(self.contacts.search(self.uid,'BEL')),1)
        self.assertEqual(len(self.contacts.search(self.uid,'092255')),1)
        self.assertEqual(len(self.contacts.search(self.uid,'ANHA@')),1)
        self.assertEqual(len(self.contacts.search(self.uid,'%')),0)

    def test_uc12_filter_group_and_favorite(self):
        gid=self.groups.create(self.uid,'Work')
        a=self.make_contact('A',phone='111222333',group_ids=[gid]);self.make_contact('B',phone='222333444',email='b@home.com')
        self.contacts.toggle_favorite(self.uid,a)
        self.assertEqual(len(self.contacts.list_contacts(self.uid,group_id=gid,favorites=True,keyword='A')),1)

    def test_uc13_sort(self):
        self.make_contact('Zed');self.make_contact('Amy',phone='222222333',email='amy@example.com')
        self.assertEqual([c.name for c in self.contacts.sort(self.uid)][:2],['Amy','Zed'])
        self.assertEqual([c.name for c in self.contacts.sort(self.uid,'Z-A')][:2],['Zed','Amy'])

    def test_uc14_create_group(self):
        gid=self.groups.create(self.uid,'Family')
        self.assertEqual(self.groups.list_groups(self.uid)[0].id,gid)
        with self.assertRaises(AppError):self.groups.create(self.uid,'family')
        with self.assertRaises(AppError):self.groups.create(self.uid,'')

    def test_uc15_rename_group_members_unchanged(self):
        gid=self.groups.create(self.uid,'Friends');cid=self.make_contact(group_ids=[gid])
        self.groups.rename(self.uid,gid,'Work')
        self.assertEqual(self.groups.list_groups(self.uid)[0].name,'Work')
        self.assertEqual(self.contacts.get(self.uid,cid).groups[0].id,gid)

    def test_uc16_delete_group_keeps_contacts(self):
        gid=self.groups.create(self.uid,'Family');cid=self.make_contact(group_ids=[gid])
        with self.assertRaises(AppError):self.groups.delete(self.uid,gid)
        self.groups.delete(self.uid,gid,confirmed=True)
        self.assertFalse(self.groups.list_groups(self.uid))
        self.assertEqual(self.contacts.get(self.uid,cid).groups,[])

    def test_uc17_multigroup_add_remove(self):
        a=self.groups.create(self.uid,'Family');b=self.groups.create(self.uid,'Work')
        cid=self.make_contact()
        self.groups.add_contact(self.uid,a,[cid,cid])
        self.groups.add_contact(self.uid,b,[cid]);self.groups.add_contact(self.uid,b,[cid])
        self.assertEqual({g.id for g in self.contacts.get(self.uid,cid).groups},{a,b})
        self.groups.remove_contact(self.uid,a,cid)
        self.assertEqual([g.id for g in self.contacts.get(self.uid,cid).groups],[b])
        with self.assertRaises(AppError):self.groups.add_contact(self.uid,a,[self.contacts.create(self.other,name='Other')])

    def test_uc18_csv_import_skip_and_no_auto_merge(self):
        path=Path(self.tmp.name)/'sample.csv'
        path.write_text('name,phone,email,address\nAmy,123456789,amy@example.com,Street\n,broken,no-email,\nAmy,123456789,amy@example.com,Street\n',encoding='utf-8')
        result=self.io.importFile(self.uid,str(path))
        self.assertEqual((result['imported'],result['skipped']),(2,1))
        self.assertEqual(len(self.contacts.findDuplicates(self.uid)),1)

    def test_uc18_vcf_import(self):
        path=Path(self.tmp.name)/'people.vcf'
        path.write_text('BEGIN:VCARD\nVERSION:3.0\nFN:Nam Nguyen\nTEL:012345678\nEMAIL:nam@example.com\nEND:VCARD\n',encoding='utf-8')
        self.assertEqual(self.io.importFile(self.uid,str(path))['imported'],1)
        self.assertEqual(self.contacts.get(self.uid,self.contacts.list_contacts(self.uid)[0].id).email,'nam@example.com')

    def test_uc19_export_csv_group_and_trash_excluded(self):
        gid=self.groups.create(self.uid,'Work')
        a=self.make_contact(group_ids=[gid]);b=self.make_contact('B',phone='0911222333',email='b@example.com')
        self.contacts.delete(self.uid,b,confirmed=True)
        output=Path(self.tmp.name)/'out.csv'
        self.assertEqual(self.io.exportFile(self.uid,str(output),group_id=gid),1)
        with output.open(encoding='utf-8-sig',newline='') as f:
            self.assertEqual(len(list(csv.DictReader(f))),1)

    def test_uc19_export_vcf_roundtrip_multiple_values(self):
        self.make_contact(phone='111222333; 222333444',email='first@example.com; second@example.com')
        contact = self.contacts.list_contacts(self.uid)[0]
        address = '12 Main Street; Unit 4, Building A'
        notes = 'First line\n' + r'Literal \n and \;'
        self.contacts.update(self.uid, contact.id, name=contact.name,
                             phone=contact.phone, email=contact.email,
                             address=address, notes=notes)
        out=Path(self.tmp.name)/'export.vcf'
        self.io.exportFile(self.uid,str(out))
        self.assertEqual(self.io.importFile(self.other,str(out))['imported'],1)
        other_c=self.contacts.list_contacts(self.other)[0]
        self.assertEqual(len(other_c.phones),2)
        self.assertEqual(len(other_c.emails),2)
        self.assertEqual(other_c.address, address)
        self.assertEqual(other_c.notes, notes)

    def test_uc20_merge_uc24_find_preserve_and_restore(self):
        g1=self.groups.create(self.uid,'Work');g2=self.groups.create(self.uid,'Family')
        a=self.make_contact('Alex 1',phone='111222333',email='first@example.com',group_ids=[g1])
        b=self.make_contact('Alex 2',phone='111222333; 999888777',email='second@example.com',group_ids=[g2])
        groups=self.contacts.findDuplicates(self.uid)
        self.assertEqual(len(groups),1)
        self.assertEqual(len(groups[0]),2)
        merged_id=self.contacts.merge(self.uid,[a,b],name='Merged Alex')
        merged=self.contacts.get(self.uid,merged_id)
        self.assertEqual(len(merged.phones),2)
        self.assertEqual(len(merged.emails),2)
        self.assertEqual({g.id for g in merged.groups},{g1,g2})
        self.assertEqual({c.id for c in self.contacts.list_contacts(self.uid,trash=True)},{a,b})
        self.contacts.restore(self.uid,a)
        self.assertEqual(len(self.contacts.list_contacts(self.uid)),2)

    def test_uc20_merge_invalid_rolls_back(self):
        a=self.make_contact();b=self.make_contact('B',phone='0901234567',email='b@example.com')
        with self.assertRaises(ValidationError):self.contacts.merge(self.uid,[a,b],name='')
        self.assertEqual(len(self.contacts.list_contacts(self.uid)),2)
        self.assertFalse(self.contacts.list_contacts(self.uid,trash=True))

    def test_uc21_send_email_external_app(self):
        c=self.make_contact()
        with patch('phonebook.services.webbrowser.open',return_value=True) as opener:
            EmailService(self.contacts).send_email(self.uid,c)
            self.assertEqual(opener.call_args.args[0],'mailto:alice@example.com')
        c2=self.make_contact('No email',phone='222222333',email='')
        with self.assertRaises(AppError):EmailService(self.contacts).send_email(self.uid,c2)

    def test_uc24_duplicate_only_owner_and_active(self):
        a=self.make_contact('A',phone='111222333',email='a@example.com')
        b=self.make_contact('B',phone='333444555',email='a@example.com')
        other=self.contacts.create(self.other,name='C',phone='111222333')
        self.assertEqual(len(self.contacts.findDuplicates(self.uid)),1)
        self.contacts.delete(self.uid,b,confirmed=True)
        self.assertFalse(self.contacts.findDuplicates(self.uid))


if __name__=='__main__':unittest.main()
