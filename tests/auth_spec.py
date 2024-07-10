import unittest
from init_app import app
from models import User, Organisation


class TestCases(unittest.TestCase):

    def setUp(self):
        self.app = app
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()


    def tearDown(self):
        self.app_context.pop()


    def test_welcome(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        # assert response.status_code == 200

'''
    def test_register_user(self):
        response = self.client.post('/auth/register', json={
            'firstName': 'hng',
            'lastName': 'intern',
            'email': 'hng-intern@backend.com',
            'password': 'password123',
            'phone': '1234567890'
        })
        self.assertEqual(response.status_code, 201)


    def test_duplicate_user(self):

        response = self.client.post('/auth/register', json={
            'firstName': 'hng',
            'lastName': 'intern',
            'email': 'hng-intern@backend.com',
            'password': 'password123',
            'phone': '1234567890'
        })
        self.assertEqual(response.status_code, 422)


    def test_user_login(self):

        response = self.client.post('/auth/login', json={
            'email': 'hng-intern@backend.com',
            'password': 'password123'
        })
        self.assertEqual(response.status_code, 200)


    def test_login_invalid_user(self):

        response = self.client.post('/auth/login', json={
            'email': 'stage-2-intern@hng.com',
            'password': 'password123'
        })
        self.assertEqual(response.status_code, 401)


    def test_login_without_email(self):

        response = self.client.post('/auth/login', json={
            'password': 'password123'
        })
        self.assertEqual(response.status_code, 422)


    def test_login_without_password(self):

        response = self.client.post('/auth/login', json={
            'email': 'stage-2-intern@hng.com'
        })
        self.assertEqual(response.status_code, 422)

'''
