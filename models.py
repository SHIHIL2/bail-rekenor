# Models are based on MongoDB collections
class User:
    def __init__(self, data):
        self.id = data['_id']
        self.aadhar = data['aadhar']
        self.password = data['password']
        self.user_type = data['user_type']
        self.identification = data.get('identification', None)

class Section:
    def __init__(self, data):
        self.section = data['section']
        self.details = data['details']
        self.eligibility = data['eligibility']

class Case:
    def __init__(self, data):
        self.fir = data['fir']
        self.section = data['section']
        self.details = data['details']

class Petition:
    def __init__(self, data):
        self.fir = data['fir']
        self.bail_details = data['bail_details']
        self.status = data['status']
