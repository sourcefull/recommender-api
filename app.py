from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Float
from sqlalchemy.orm import relationship
import os
from flask_marshmallow import Marshmallow
import requests
import numpy as np
import pandas as pd
import json

from marshmallow_sqlalchemy import ModelSchema


app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'recommender.db')

db = SQLAlchemy(app)
ma = Marshmallow(app)



@app.cli.command('db_create')
def db_create():
    db.create_all()
    print('Database created!')

@app.cli.command('db_drop')
def db_drop():
    db.drop_all()
    print('Database dropped!')

@app.cli.command('db_seed')
def db_seed():


    nvd_df = get_nvd_df()

    for i in range(len(nvd_df)):
        cve = nvd_df.iloc[i]['VULNID']
        version = nvd_df.iloc[i]['VERSION']
        vector = nvd_df.iloc[i]['VECTOR_STRING']
        exploit_score = nvd_df.iloc[i]['EXPLOIT_SCORE']


        vul_entry = Vulnerabilities(VULN_ID=cve,
                                 VERSION=version,
                                 VECTORSTRING=vector,
                                 EXPLOIT_SCORE=exploit_score)
        db.session.add(vul_entry)

    #nvd_df.to_sql('vulnerabilities', con = db.session.bind)


    """
    #first_domain = DomainProfile(GBU='FMW',
                     CONFIDENTIALITY_IMPACT=9,
                     INTEGRITY_IMPACT = 9,
                     AVAILABILITY_IMPACT = 9,
                     PRIVILEGES_REQUIRED = 9,
                     USER_INTERACTION = 9,
                     SCOPE = 9,
                     ATTACK_COMPLEXITY = 9,
                     ACCESS_VECTOR = 9)

    #first_user = UserProfile(IMPLICIT_PROFILE_ID = 1,
                            DOMAIN_PROFILE_ID = 1,
                            GBU = 'FMW',
                            SERVICE_ID = 1,
                            CONFIDENTIALITY_IMPACT=9,
                            INTEGRITY_IMPACT=8,
                            AVAILABILITY_IMPACT=7,
                            PRIVILEGES_REQUIRED= 8,
                            USER_INTERACTION=8,
                            SCOPE=8,
                            ATTACK_COMPLEXITY=8,
                            ACCESS_VECTOR=8)


    #implicit_user = ImplicitProfile(USER_PROFILE_ID=1,
                                    DOMAIN_PROFILE_ID=1,
                                    CONFIDENTIALITY_IMPACT=9,
                                    INTEGRITY_IMPACT=8,
                                    AVAILABILITY_IMPACT=7,
                                    PRIVILEGES_REQUIRED=8,
                                    USER_INTERACTION=8,
                                    SCOPE=8,
                                    ATTACK_COMPLEXITY=8,
                                    ACCESS_VECTOR=8)

    """
    db.session.commit()

    print('database seeded!')


@app.route('/')




@app.route('/get_oracleseverityscore/<gbu>/<service>/<cve>', methods=['GET'])
def getOracleSeverityscore(gbu = None, service = None, cve = None):
    #gbu = request.form['GBU']
    #service = request.form['SERVICE_NAME']
    #cve = request.form['CVE']
    #return jsonify(message = "gbu = {} service = {} cve = {}".format(gbu,service,cve))


    #domainprofile = DomainProfile.query.filter_by(GBU=gbu).first()
    #domainprofilequery = db.session.query(DomainProfile).filter_by(GBU=gbu).first()

    #if (not domainprofile):
    #    return jsonify(message="no domain profile found"),404
    #domain_profile = pd.read_table('domain_profile', db.session.bind)
    #w_df = domain_profile[domain_profile['GBU'] == gbu]


    #check if that CVE exists in vulnerabilities table

    vul_exists = Vulnerabilities.query.filter_by(VULN_ID = cve).first()
    if (not vul_exists):
        return jsonify(message = "That CVE does not exist in the database"), 404




    service_exists = Services.query.filter_by(GBU=gbu, SERVICE=service).first()

    # checking if the service id exists for the gbu and service
    if (not service_exists):
        return jsonify(message = "No service exists for that GBU and Service name"), 404


    service_id = service_exists.SERVICE_ID


    user_profile_exists = Services.query.filter_by(SERVICE_ID = service_id).first()


    #checking if the user profile exists for that service
    if (not user_profile_exists):
        return jsonify(message = "No user profile exists for that GBU and Service name"), 404





    w_df = pd.read_sql(sql = db.session.query(DomainProfile).with_entities(DomainProfile.SCOPE,
                                                        DomainProfile.ATTACK_COMPLEXITY,
                                                        DomainProfile.GBU,
                                                        DomainProfile.USER_INTERACTION,
                                                        DomainProfile.PRIVILEGES_REQUIRED,
                                                        DomainProfile.ACCESS_VECTOR,
                                                        DomainProfile.AVAILABILITY_IMPACT,
                                                        DomainProfile.INTEGRITY_IMPACT,
                                                        DomainProfile.CONFIDENTIALITY_IMPACT).statement,
                                                        con = db.session.bind)
    w_df = w_df[w_df['GBU'] == gbu]





    exist_record = VulRecord.query.filter_by(VULN_ID = cve, SERVICE_ID = service_id).first()
    if (not exist_record):

        new_vul_record = VulRecord(VULN_ID = cve,
                               SERVICE_ID = service_id)

        db.session.add(new_vul_record)
        db.session.commit()


    u_df = pd.read_sql(sql=db.session.query(UserProfile).with_entities(UserProfile.SCOPE,
                                                                    UserProfile.ATTACK_COMPLEXITY,
                                                                    UserProfile.USER_INTERACTION,
                                                                    UserProfile.PRIVILEGES_REQUIRED,
                                                                    UserProfile.ACCESS_VECTOR,
                                                                    UserProfile.AVAILABILITY_IMPACT,
                                                                    UserProfile.INTEGRITY_IMPACT,
                                                                    UserProfile.CONFIDENTIALITY_IMPACT,
                                                                    UserProfile.SERVICE_ID,
                                                                    UserProfile.USER_PROFILE_ID).statement,
                                                                    con=db.session.bind)
    u_df = u_df[u_df['SERVICE_ID'] == service_id] # getting user profile from the service id

    userprofile_id = u_df.iloc[0]['USER_PROFILE_ID']


    u_hat_df = pd.read_sql(sql=db.session.query(ImplicitProfile).with_entities(ImplicitProfile.SCOPE,
                                                                                ImplicitProfile.ATTACK_COMPLEXITY,
                                                                                 ImplicitProfile.INTEGRITY_IMPACT,
                                                                                 ImplicitProfile.USER_INTERACTION,
                                                                                 ImplicitProfile.PRIVILEGES_REQUIRED,
                                                                                 ImplicitProfile.ACCESS_VECTOR,
                                                                                 ImplicitProfile.AVAILABILITY_IMPACT,
                                                                                 ImplicitProfile.CONFIDENTIALITY_IMPACT,
                                                                                 ImplicitProfile.USER_PROFILE_ID).statement,
                                                                                con=db.session.bind)



    u_hat_df = u_hat_df[u_hat_df['USER_PROFILE_ID'] == userprofile_id] #getting the implicit profile from the user profile






    w = get_profilevec(w_df)
    u = get_profilevec(u_df)
    u_hat = get_profilevec(u_hat_df)

    v = vulnerability_vec(cve)
    score = recom_score(u, u_hat, w, v)
    final_score = round(10*score, 2)

    return jsonify(message = "oracle severity score is {}".format(final_score))

#vulnerability records get

@app.route('/vul_records', methods = ['GET'])
def vulRecord():

    vulRecord_list = VulRecord.query.all()
    result = VulRecords_Schema.dump(vulRecord_list)
    return jsonify(result)


#update implicit profile using implicit feedback

@app.route('/update_implicit/<gbu>/<service>/<cve>', methods = ['PUT'])
def updateImplicit(gbu=None, service=None, cve=None):
    v = vulnerability_vec(cve)
    v = np.delete(v, 3)
    service = Services.query.filter_by(GBU=gbu, SERVICE=service).first()

    if (service):

        service_id = service.SERVICE_ID
        userprofile = UserProfile.query.filter_by(SERVICE_ID=service_id).first()
        if (not userprofile):
            return jsonify(message = "no user profile or implicit profile has been created for that GBU and service name"), 404

        userprofile_id = userprofile.USER_PROFILE_ID
        implicitprofile = ImplicitProfile.query.filter_by(USER_PROFILE_ID=userprofile_id).first()
        new_u_hat = update_mer_mma(implicitprofile, v)

        implicitprofile.CONFIDENTIALITY_IMPACT = new_u_hat[0]
        implicitprofile.INTEGRITY_IMPACT = new_u_hat[1]
        implicitprofile.AVAILABILITY_IMPACT = new_u_hat[2]
        implicitprofile.ATTACK_COMPLEXITY = new_u_hat[3]
        implicitprofile.PRIVILEGES_REQUIRED = new_u_hat[4]
        implicitprofile.USER_INTERACTION = new_u_hat[5]
        implicitprofile.SCOPE = new_u_hat[6]
        implicitprofile.ACCESS_VECTOR = new_u_hat[7]
        db.session.commit()
        return jsonify(message = "implicit profile update complete"), 202


    else:
        return jsonify(message = "no service found for that gbu and service name"), 404




#gets the implicit profiles

@app.route('/implicit_profiles', methods=['GET'])
def implicitProfile():

    implicitProfile_list = ImplicitProfile.query.all()
    result = ImplicitProfiles_Schema.dump(implicitProfile_list)




    return jsonify(result)


#User Profiles add, get,


@app.route('/add_user_profile', methods=['POST'])
def add_user_profile():
     GBU = request.form['GBU']
     SERVICE = request.form['SERVICE_NAME']


     test_service = Services.query.filter_by(GBU=GBU, SERVICE=SERVICE).first()
     if not test_service:
         return jsonify("Service does not exist with that GBU and SERVICE NAME"), 409


     test_user_profile = UserProfile.query.filter_by(SERVICE_ID=test_service.SERVICE_ID).first()
     if test_user_profile:
         return jsonify("There is already a user profile with that GBU, and SERVICE"), 409

     test_domain_profile = DomainProfile.query.filter_by(GBU=GBU).first()
     if not test_domain_profile:
         return jsonify("Domain profile for that GBU does not exist"), 404


     CONFIDENTIALITY_IMPACT = request.form['CONFIDENTIALITY_IMPACT']
     INTEGRITY_IMPACT = request.form['INTEGRITY_IMPACT']
     AVAILABILITY_IMPACT = request.form['AVAILABILITY_IMPACT']
     PRIVILEGES_REQUIRED = request.form['PRIVILEGES_REQUIRED']
     USER_INTERACTION = request.form['USER_INTERACTION']
     SCOPE = request.form['SCOPE']
     ATTACK_COMPLEXITY = request.form['ATTACK_COMPLEXITY']
     ACCESS_VECTOR = request.form['ACCESS_VECTOR']
     #DOMAIN_PROFILE_ID = test_domain_profile.DOMAIN_PROFILE_ID


     new_user_profile = UserProfile(#DOMAIN_PROFILE_ID = DOMAIN_PROFILE_ID,
                                     GBU = GBU,
                                     SERVICE_ID = test_service.SERVICE_ID,
                                     CONFIDENTIALITY_IMPACT = CONFIDENTIALITY_IMPACT,
                                     INTEGRITY_IMPACT = INTEGRITY_IMPACT,
                                     AVAILABILITY_IMPACT = AVAILABILITY_IMPACT,
                                     PRIVILEGES_REQUIRED = PRIVILEGES_REQUIRED,
                                     USER_INTERACTION = USER_INTERACTION,
                                     SCOPE = SCOPE,
                                     ATTACK_COMPLEXITY = ATTACK_COMPLEXITY,
                                     ACCESS_VECTOR = ACCESS_VECTOR)

     new_user_profile.domainprofile = test_domain_profile
     db.session.add(new_user_profile)
     #db.session.commit()
     #user_id = new_user_profile.USER_PROFILE_ID

     new_implicit_profile = ImplicitProfile(#USER_PROFILE_ID = user_id,
                                 #DOMAIN_PROFILE_ID = DOMAIN_PROFILE_ID,
                                 CONFIDENTIALITY_IMPACT=CONFIDENTIALITY_IMPACT,
                                 INTEGRITY_IMPACT=INTEGRITY_IMPACT,
                                 AVAILABILITY_IMPACT=AVAILABILITY_IMPACT,
                                 PRIVILEGES_REQUIRED=PRIVILEGES_REQUIRED,
                                 USER_INTERACTION=USER_INTERACTION,
                                 SCOPE=SCOPE,
                                 ATTACK_COMPLEXITY=ATTACK_COMPLEXITY,
                                 ACCESS_VECTOR=ACCESS_VECTOR)


     new_implicit_profile.userprofile = new_user_profile
     new_implicit_profile.domainprofile = test_domain_profile
     db.session.add(new_implicit_profile)
     db.session.commit()
     return jsonify(message="You added a user profile"), 201





@app.route('/user_profiles', methods=['GET'])
def userProfile():

    userProfile_list = UserProfile.query.all()
    result = UserProfiles_Schema.dump(userProfile_list)
    return jsonify(result)


@app.route('/user_profile_details/<int:profile_id>', methods = ["GET"])
def user_profile_details(profile_id:int):
    user_profile = UserProfile.query.filter_by(USER_PROFILE_ID=profile_id).first()
    if user_profile:
        result = UserProfile_Schema.dump(user_profile)
        return jsonify(result)
    else:
        return jsonify(message="That user profile does not exist"), 404


# Service Get, Post, Delete



@app.route('/services', methods=['GET'])
def services():
    service_list = Services.query.all()
    result = Services_Schema.dump(service_list)
    return jsonify(result)


@app.route('/add_service', methods = ['POST'])
def add_service():
    gbu = request.form['GBU']
    service = request.form['SERVICE_NAME']

    test_service = Services.query.filter_by(GBU=gbu, SERVICE=service).first()
    if test_service:
        return jsonify("There is already a service with that GBU, and SERVICE_NAME"), 409
    else:
        new_service = Services(GBU=gbu, SERVICE=service)
        db.session.add(new_service)
        db.session.commit()
        return jsonify(message="You added a service"), 201


@app.route('/remove_service/<int:service_id>', methods = ['DELETE'])
def remove_service(service_id:int):
    service = Services.query.filter_by(SERVICE_ID=service_id).first()
    if (service):
        db.session.delete(service)
        db.session.commit()
        return jsonify(message="you deleted a service"), 202
    else:
        return jsonify(messave="That service does not exist"), 404


# Domain Profile Get, Post, Put, Delete
@app.route('/domain_profiles', methods=['GET'])
def domainProfile():
    domainProfile_list = DomainProfile.query.all()
    result = DomainProfiles_Schema.dump(domainProfile_list)
    return jsonify(result)


@app.route('/domain_profile_details/<int:profile_id>', methods = ["GET"])
def domain_profile_details(profile_id:int):
    domain_profile = DomainProfile.query.filter_by(DOMAIN_PROFILE_ID=profile_id).first()
    if domain_profile:
        result = DomainProfile_Schema.dump(domain_profile)
        return jsonify(result)
    else:
        return jsonify(message="That domain profile does not exist"), 404


@app.route('/add_domain_profile', methods = ['POST'])
def add_domain_profile():
    GBU = request.form['GBU']
    test = DomainProfile.query.filter_by(GBU=GBU).first()
    exist_service = Services.query.filter_by(GBU=GBU).first()

    if not exist_service:
        return jsonify(message= "No service has been found for that GBU"), 404

    if test:
        return jsonify(message = "There is already a domain profile for that GBU"), 409
    else:
        CONFIDENTIALITY_IMPACT = request.form['CONFIDENTIALITY_IMPACT']
        INTEGRITY_IMPACT = request.form['INTEGRITY_IMPACT']
        AVAILABILITY_IMPACT = request.form['AVAILABILITY_IMPACT']
        PRIVILEGES_REQUIRED = request.form['PRIVILEGES_REQUIRED']
        USER_INTERACTION = request.form['USER_INTERACTION']
        SCOPE = request.form['SCOPE']
        ATTACK_COMPLEXITY = request.form['ATTACK_COMPLEXITY']
        ACCESS_VECTOR = request.form['ACCESS_VECTOR']
        new_domain_profile = DomainProfile(GBU = GBU,
                                           CONFIDENTIALITY_IMPACT = CONFIDENTIALITY_IMPACT,
                                           INTEGRITY_IMPACT = INTEGRITY_IMPACT,
                                           AVAILABILITY_IMPACT=AVAILABILITY_IMPACT,
                                           PRIVILEGES_REQUIRED=PRIVILEGES_REQUIRED,
                                           USER_INTERACTION=USER_INTERACTION,
                                           SCOPE=SCOPE,
                                           ATTACK_COMPLEXITY=ATTACK_COMPLEXITY,
                                           ACCESS_VECTOR=ACCESS_VECTOR)
        db.session.add(new_domain_profile)
        db.session.commit()
        return jsonify(message="You added a domain profile"), 201


@app.route('/remove_domain_profile/<int:profile_id>', methods = ['DELETE'])
def remove_domain_profile(profile_id:int):
    domain_profile = DomainProfile.query.filter_by(DOMAIN_PROFILE_ID=profile_id).first()
    if domain_profile:
        db.session.delete(domain_profile)
        db.session.commit()
        return jsonify(message="You deleted a domain profile"), 202
    else:
        return jsonify(message="That domain profile does not exist"), 404



# database models
class VulRecord(db.Model):
    __tablename__ = 'vulnerabilityrecord'

    ID = db.Column(Integer, primary_key = True)
    VULN_ID = db.Column(String)
    SERVICE_ID = db.Column(Integer, db.ForeignKey('services.SERVICE_ID'), nullable=False)
    services = relationship("Services", back_populates="vulnerabilityrecord")


class Vulnerabilities(db.Model):

    __tablename__ = 'vulnerabilities'

    ID = db.Column(Integer, primary_key=True)
    VULN_ID = db.Column(String)
    VERSION = db.Column(String)
    VECTORSTRING = db.Column(String)
    EXPLOIT_SCORE = db.Column(String)


class UserProfile(db.Model):

    __tablename__ = 'userprofile'

    USER_PROFILE_ID = db.Column(Integer, primary_key=True)
    #IMPLICIT_PROFILE_ID = db.Column(Integer, db.ForeignKey('implicitprofile.IMPLICIT_PROFILE_ID'), nullable=False)
    DOMAIN_PROFILE_ID = db.Column(Integer, db.ForeignKey('domainprofile.DOMAIN_PROFILE_ID'), nullable=False)
    GBU = db.Column(String)
    SERVICE_ID = db.Column(Integer, db.ForeignKey('services.SERVICE_ID'), nullable=False, unique=True)
    CONFIDENTIALITY_IMPACT = db.Column(Integer)
    INTEGRITY_IMPACT = db.Column(Integer)
    AVAILABILITY_IMPACT = db.Column(Integer)
    PRIVILEGES_REQUIRED = db.Column(Integer)
    USER_INTERACTION = db.Column(Integer)
    SCOPE = db.Column(Integer)
    ATTACK_COMPLEXITY = db.Column(Integer)
    ACCESS_VECTOR = db.Column(Integer)

    domainprofile = relationship("DomainProfile", back_populates="userprofile")
    implicitprofile = relationship("ImplicitProfile", back_populates="userprofile", cascade="all, delete")


class ImplicitProfile(db.Model):

    __tablename__ = 'implicitprofile'

    IMPLICIT_PROFILE_ID = db.Column(Integer, primary_key=True)
    USER_PROFILE_ID = db.Column(Integer, db.ForeignKey('userprofile.USER_PROFILE_ID'), nullable=False, unique = True)
    DOMAIN_PROFILE_ID = db.Column(Integer, db.ForeignKey('domainprofile.DOMAIN_PROFILE_ID'), nullable=False, unique = True)#, nullable=False)
    CONFIDENTIALITY_IMPACT = db.Column(Float)
    INTEGRITY_IMPACT = db.Column(Float)
    AVAILABILITY_IMPACT = db.Column(Float)
    PRIVILEGES_REQUIRED = db.Column(Float)
    USER_INTERACTION = db.Column(Float)
    SCOPE = db.Column(Float)
    ATTACK_COMPLEXITY = db.Column(Float)
    ACCESS_VECTOR = db.Column(Float)

    domainprofile = relationship("DomainProfile", back_populates="implicitprofile")
    userprofile = relationship("UserProfile", back_populates="implicitprofile")


class DomainProfile(db.Model):

    __tablename__ = 'domainprofile'

    DOMAIN_PROFILE_ID = db.Column(Integer, primary_key = True)
    GBU = db.Column(String)
    CONFIDENTIALITY_IMPACT = db.Column(Integer)
    INTEGRITY_IMPACT = db.Column(Integer)
    AVAILABILITY_IMPACT = db.Column(Integer)
    PRIVILEGES_REQUIRED = db.Column(Integer)
    USER_INTERACTION = db.Column(Integer)
    SCOPE = db.Column(Integer)
    ATTACK_COMPLEXITY = db.Column(Integer)
    ACCESS_VECTOR = db.Column(Integer)

    userprofile = relationship("UserProfile", back_populates="domainprofile", cascade="all, delete")
    implicitprofile = relationship("ImplicitProfile", back_populates="domainprofile", cascade="all, delete")


"""
class CveVulnerabilities(db.Model):
    __tablename__ = 'cvevulnerabilities'

    VULN_ID = db.Column(Integer, primary_key = True)
    CVE_ID = db.Column(String)
    SERVICE_ID = db.Column(Integer, db.ForeignKey('services.SERVICE_ID'), nullable=False)
"""


class Services(db.Model):
    __tablename__ = 'services'

    SERVICE_ID = db.Column(Integer, primary_key=True)
    GBU = db.Column(String)
    SERVICE = db.Column(String)

    #VERSION = db.Column(String)

    #Cvevulnerabilities = relationship("CveVulnerabilities", cascade="all, delete")
    vulnerabilityrecord = relationship("VulRecord", back_populates = "services", cascade="all, delete")


class ServiceSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        ordered = True
        model = Services
        include_relationships = True
        load_instance = True



class UserProfileSchema(ma.SQLAlchemySchema):
    class Meta:
        ordered = True
        model = UserProfile
        include_fk = True
        include_relationships = True
        load_instance = True




class DomainProfileSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        ordered = True
        model = DomainProfile
        include_relationships = True
        load_instance = True

    """
    DOMAIN_PROFILE_ID = ma.auto_field()
    GBU = ma.auto_field()
    CONFIDENTIALITY_IMPACT = ma.auto_field()
    INTEGRITY_IMPACT = ma.auto_field()
    AVAILABILITY_IMPACT = ma.auto_field()
    PRIVILEGES_REQUIRED = ma.auto_field()
    USER_INTERACTION = ma.auto_field()
    SCOPE = ma.auto_field()
    ATTACK_COMPLEXITY = ma.auto_field()
    ACCESS_VECTOR = ma.auto_field()
    """

class ImplicitProfileSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        ordered = True
        model = ImplicitProfile
        include_relationships = True
        include_fk = True
        load_instance = True


class VulRecordSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        ordered = True
        model = VulRecord
        include_relationships = True
        include_fk = True
        load_instance = True



VulRecord_Schema = VulRecordSchema()
VulRecords_Schema = VulRecordSchema(many=True)


ImplicitProfile_Schema = ImplicitProfileSchema()
ImplicitProfiles_Schema = ImplicitProfileSchema(many=True)

Service_Schema = ServiceSchema()
Services_Schema = ServiceSchema(many=True)

UserProfile_Schema = UserProfileSchema()
UserProfiles_Schema = UserProfileSchema(many=True)

DomainProfile_Schema = DomainProfileSchema()
DomainProfiles_Schema = DomainProfileSchema(many=True)


def get_nvd_df():
    path = os.getcwd()
    files = os.listdir(path + '/CVE_json')
    files_json = [f for f in files if f[-4:] == 'json']

    columns = ['VULNID', 'VERSION', 'VECTOR_STRING', 'EXPLOIT_SCORE']
    df_list = []
    for file in files_json:
        data_nvd = json.load(open(path + '/CVE_json/' + file))
        for item in data_nvd['CVE_Items']:
            cve = item['cve']['CVE_data_meta']['ID']
            if not item['impact']:
                continue

            if 'baseMetricV3' in item['impact']:
                vectorString = item['impact']['baseMetricV3']['cvssV3']['vectorString']
                version = 'baseMetricV3'
                exploit_score = item['impact']['baseMetricV3']['exploitabilityScore']
            else:
                # print(item['impact'].keys())


                vectorString = item['impact']['baseMetricV2']['cvssV2']['vectorString']
                version = 'baseMetricV2'
                exploit_score = item['impact']['baseMetricV2']['exploitabilityScore']

            list_temp = [cve, version, vectorString, exploit_score]
            my_dict = dict(zip(columns, list_temp))
            df_list.append(my_dict)

    df_artifacts = pd.DataFrame(df_list).drop_duplicates()
    return df_artifacts


def createCVEdict(cve):

    #result = Vulnerabilities.query.filter_by(VULN_ID = cve).first()
    vuln_df = pd.read_sql(sql=db.session.query(Vulnerabilities).with_entities(Vulnerabilities.VULN_ID,
                                                                         Vulnerabilities.VERSION,
                                                                         Vulnerabilities.VECTORSTRING,
                                                                         Vulnerabilities.EXPLOIT_SCORE).statement,
                                                                         con=db.session.bind)

    cve_df = vuln_df[vuln_df['VULN_ID'] == cve].reset_index(drop=True)
    base_metric = cve_df.iloc[0]['VERSION']



    cve_dict = dict()

    conv_dict = dict()
    attvec_dict = dict()
    conv_dict['H'] = 'HIGH'
    conv_dict['L'] = 'LOW'
    conv_dict['N'] = 'NONE'
    conv_dict['R'] = 'REQUIRED'
    conv_dict['U'] = 'UNCHANGED'
    conv_dict['C'] = 'CHANGED'
    conv_dict['NS'] = 'NO_SCOPE'
    attvec_dict['N'] = 'NETWORK'
    attvec_dict['A'] = 'ADJACENT'
    attvec_dict['L'] = 'LOCAL'
    attvec_dict['P'] = 'PHYSICAL'

    def list_to_dict(rlist):
        return dict(map(lambda s: s.split(':'), rlist))
    vec_string = cve_df.iloc[0]['VECTORSTRING']
    exploitscore = cve_df.iloc[0]['EXPLOIT_SCORE']

    def convert_vec_dict(vec_dict):

        #Attack complexity conversion
        if vec_dict['AC'] == 'H':
            vec_dict['UI'] = 'R'
        elif vec_dict['AC'] == 'M':
            vec_dict['UI'] = 'R'
            vec_dict['AC'] = 'L'
        else:
            vec_dict['UI'] = 'N'


        #Authorization conversion
        if vec_dict['Au'] == 'M':
            vec_dict['PR'] = 'H'
        elif vec_dict['Au'] == 'S':
            vec_dict['PR'] = 'L'
        else:
            vec_dict['PR'] = 'N'

        if vec_dict['C'] == 'C':

            vec_dict['C'] = 'H'
        elif vec_dict['C'] == 'P':
            vec_dict['C'] = 'L'


        if vec_dict['I'] == 'C':
            vec_dict['I'] = 'H'
        elif vec_dict['I'] == 'P':
            vec_dict['I'] = 'L'

        if vec_dict['A'] == 'C':
            vec_dict['A'] = 'H'
        elif vec_dict['A'] == 'P':
            vec_dict['A'] = 'L'

        vec_dict['S'] = 'NS'

        return vec_dict



    if (base_metric == 'baseMetricV3'):
        vec_list = vec_string.split('/')[1:]
        vec_dict = list_to_dict(vec_list)

    else:
        vec_list = vec_string.split('/')
        vec_dict = list_to_dict(vec_list)
        vec_dict = convert_vec_dict(vec_dict)

    cve_dict['confidentiality_impact'] = conv_dict[vec_dict['C']]
    cve_dict['integrity_impact'] = conv_dict[vec_dict['I']]
    cve_dict['availability_impact'] = conv_dict[vec_dict['A']]
    cve_dict['exploitability_score'] = float(exploitscore)
    cve_dict['att_complex'] = conv_dict[vec_dict['AC']]
    cve_dict['privileges_required'] = conv_dict[vec_dict['PR']]
    cve_dict['user_interaction'] = conv_dict[vec_dict['UI']]
    cve_dict['scope'] = conv_dict[vec_dict['S']]
    cve_dict['attack_vector'] = attvec_dict[vec_dict['AV']]






    return cve_dict



def vulnerability_vec(cve):
    impact_dict = dict()
    impact_dict['NONE'] = 0
    impact_dict['LOW'] = 0.5
    impact_dict['HIGH'] = 1.0

    AV_dict = dict()
    AV_dict['NETWORK'] = 1.0
    AV_dict['ADJACENT_NETWORK'] = 0.6
    AV_dict['LOCAL'] = 0.3
    AV_dict['PHYSICAL'] = 0

    AC_dict = dict()
    AC_dict['LOW'] = 1.0
    AC_dict['HIGH'] = 0

    PR_dict = dict()
    PR_dict['NONE'] = 1.0
    PR_dict['LOW'] = 0.5
    PR_dict['HIGH'] = 0

    UI_dict = dict()
    UI_dict['NONE'] = 1.0
    UI_dict['REQUIRED'] = 0

    Scope_dict = dict()
    Scope_dict['CHANGED'] = 1.0
    Scope_dict['NO_SCOPE'] = 0.5
    Scope_dict['UNCHANGED'] = 0



    cve_dict = createCVEdict(cve)


    # impact feature vectors
    confidentiality_score = impact_dict[cve_dict['confidentiality_impact']]
    integrity_score = impact_dict[cve_dict['integrity_impact']]
    availability_score = impact_dict[cve_dict['availability_impact']]

    # exploitability
    # this determines the ease of exploiting the vulnerability
    exploitability_score = cve_dict['exploitability_score']

    #exploit features
    att_complex_score = AC_dict[cve_dict['att_complex']]
    priv_required_score = PR_dict[cve_dict['privileges_required']]
    user_interaction_score = UI_dict[cve_dict['user_interaction']]
    scope_score = Scope_dict[cve_dict['scope']]
    attack_vec_score = AV_dict[cve_dict['attack_vector']]

    return np.array([confidentiality_score, integrity_score, availability_score, exploitability_score,
                     att_complex_score, priv_required_score, user_interaction_score, scope_score, attack_vec_score])


def sim_dist(t, v):
    """

    Input
    ----------
    t : Type numpy array
        DESCRIPTION. user profile feature vector
    v : TYPE numpy array
        DESCRIPTION. vulnerability feature vector

    Returns
    -------
    TYPE numpy array
        DESCRIPTION the similarity of each of the features between t and v

    """

    conf_sim = 1 - abs(t[0] - v[0])
    integrity_sim = 1 - abs(t[1] - v[1])
    availability_sim = 1 - abs(t[2] - v[2])
    exploit_sim = 1 - abs(10 - v[3]) / 10
    attack_complex_sim = 1 - abs(t[3] - v[4])
    priv_sim = 1 - abs(t[4] - v[5])
    interact_sim = 1 - abs(t[5] - v[6])
    scope_sim = 1 - abs(t[6] - v[7])
    attack_sim = 1 - abs(t[7] - v[8])

    return np.array(
        [conf_sim, integrity_sim, availability_sim, exploit_sim, attack_complex_sim, priv_sim, interact_sim, scope_sim,
         attack_sim])


def get_profilevec(df):
    confidentiality_score = (df.iloc[0]['CONFIDENTIALITY_IMPACT']) / 10
    integrity_score = (df.iloc[0]['INTEGRITY_IMPACT']) / 10
    availability_score = (df.iloc[0]['AVAILABILITY_IMPACT']) / 10
    attack_vector_score = (df.iloc[0]['ACCESS_VECTOR']) / 10
    att_complex_score = (df.iloc[0]['ATTACK_COMPLEXITY']) / 10
    privileges_required_score = (df.iloc[0]['PRIVILEGES_REQUIRED']) / 10
    user_interaction_score = (df.iloc[0]['USER_INTERACTION']) / 10
    scope_score = (df.iloc[0]['SCOPE']) / 10

    return np.asarray(
        [confidentiality_score, integrity_score, availability_score, att_complex_score, privileges_required_score,
         user_interaction_score, scope_score, attack_vector_score])

def update_mer_mma(implicitprofile, v):


    conf_impact = implicitprofile.CONFIDENTIALITY_IMPACT
    int_impact = implicitprofile.INTEGRITY_IMPACT
    avail_impact = implicitprofile.AVAILABILITY_IMPACT
    privil_required = implicitprofile.PRIVILEGES_REQUIRED
    user_interaction = implicitprofile.USER_INTERACTION
    scope = implicitprofile.SCOPE
    attack_complex = implicitprofile.ATTACK_COMPLEXITY
    access_vec = implicitprofile.ACCESS_VECTOR

    u_hat_array = np.array([conf_impact, int_impact, avail_impact, attack_complex, privil_required, user_interaction, scope,
                            access_vec])/10

    S = 3
    u_hat = ((S-1)*u_hat_array + v)/S
    return (u_hat * 10)






def recom_score(u, u_hat, w, v):
    sim_wv = sim_dist(w, v)
    sim_uv = sim_dist(u, v)
    sim_uhatv = sim_dist(u_hat, v)

    conf_plus = 0.3 * sim_wv[0] + 0.35 * sim_uv[0] + 0.35 * sim_uhatv[0]
    integrity_plus = 0.3 * sim_wv[1] + 0.35 * sim_uv[1] + 0.35 * sim_uhatv[1]
    avail_plus = 0.3 * sim_wv[2] + 0.35 * sim_uv[2] + 0.35 * sim_uhatv[2]

    exploit_plus = 0.8 * sim_uv[3] + 0.2 * sim_uhatv[3]

    complex_plus = 0.3 * sim_wv[4] + 0.35 * sim_uv[4] + 0.35 * sim_uhatv[4]

    priv_plus = 0.3 * sim_wv[5] + 0.35 * sim_uv[5] + 0.35 * sim_uhatv[5]

    interac_plus = 0.3 * sim_wv[6] + 0.35 * sim_uv[6] + 0.35 * sim_uhatv[6]

    scope_plus = 0.3 * sim_wv[7] + 0.35 * sim_uv[7] + 0.35 * sim_uhatv[7]

    attack_plus = 0.3 * sim_wv[8] + 0.35 * sim_uv[8] + 0.35 * sim_uhatv[8]

    U_output = (conf_plus + integrity_plus + avail_plus + exploit_plus + complex_plus + priv_plus +
                interac_plus + scope_plus + attack_plus) / 9

    return U_output




if __name__ == '__main__':
    app.run()


