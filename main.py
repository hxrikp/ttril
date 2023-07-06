from presidio_analyzer import AnalyzerEngine, RecognizerResult, EntityRecognizer, Pattern, PatternRecognizer
from preprocessing import transform_keys
import spacy
import json

class PIIEntityRecognizer(EntityRecognizer):
    def __init__(self):
        self.supported_entities = ["PII"]
        super().__init__(supported_entities=self.supported_entities)

    def load(self):
        # Load the spaCy NLP model for named entity recognition
        self.nlp = spacy.load("en_core_web_lg")

    def analyze(self, text, entities, nlp_artifacts):
        results = []

        # Use the pre-trained NER model to recognize PII entities
        doc = self.nlp(text)
        for ent in doc.ents:
            if ent.label_ in ["PII"]:
                # Create a RecognizerResult object for each PII entity
                result = RecognizerResult(
                    entity_type="PII",
                    start=ent.start_char,
                    end=ent.end_char,
                    score=0.5
                )
                results.append(result)

        return results

# Instantiate the PIIEntityRecognizer class
pii_entity_recognizer = PIIEntityRecognizer()

# Load the necessary NLP artifacts for PII entity recognition
pii_entity_recognizer.load()


pattern_random = Pattern(name="random_pattern", regex=r"(?=.*\d.*\d).+", score=0.8)
pattern_numbers = Pattern(name="numbers_pattern", regex=r"\b\d{2,}\b", score=0.85)
pattern_aadhaar = Pattern(name="aadhaar_pattern", regex=r"\b\d{4}\s\d{4}\s\d{4}\b|\b\d{12,}\b", score=1.0)
pattern_voter_id = Pattern(name="voter_id_pattern", regex=r"\b[A-Z]{3}\d{7}\b", score=1.0)
pattern_pan_card = Pattern(name="pan_card_pattern", regex=r"[A-Z]{5}\d{4}[A-Z]{1}", score=1.0)
pattern_credit_card = Pattern(name="credit_card_pattern", regex=r"^(?:4[0-9]{12}(?:[0-9]{3})?|[25][1-7][0-9]{14}|6(?:011|5[0-9]{2})[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{2})\d{11})$", score=1.0)
pattern_bank_account = Pattern(name="bank_account_pattern", regex=r"\b\d{9,18}\b", score=0.5)
pattern_driver_license = Pattern(name="driver_license_pattern", regex=r"[A-Z]{2}[0-9]{2}(?:19|20)\d{2}(?:19|20|21)\d{7}", score=1.0)
pattern_email = Pattern(name="email_pattern", regex=r"^[\w\.=-]+@[\w\.-]+\.[\w]{2,3}$", score=0.9)
pattern_ssn = Pattern(name="ssn_pattern", regex=r"\b(?!000|666|9\d{2})([0-8]\d{2}|7([0-6]\d))([-]?|\s{1})(?!00)\d\d\2(?!0000)\d{4}\b", score=0.9)
pattern_ip = Pattern(name="ip_pattern", regex=r"^\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}$", score=0.9)
pattern_date = Pattern(name="date_pattern", regex=r"^([1][12]|[0]?[1-9])[\/-]([3][01]|[12]\d|[0]?[1-9])[\/-](\d{4}|\d{2})$", score=0.9)
pattern_passport = Pattern(name="passport_pattern", regex=r"[A-Z]{1}[0-9]{7}", score=0.9)
pattern_phone_number = Pattern(name="phone_number_pattern", regex=r"\b\d{10}\b|\+91[-\s]?\d{10}\b", score=1.0)
pattern_upi_id = Pattern(name="upi_id_pattern", regex=r"^[a-zA-Z0-9.-]{2,256}@[a-zA-Z][a-zA-Z]{2,64}$", score=1.0)


random_recognizer = PatternRecognizer(supported_entity="Potential_PII", patterns=[pattern_random])
number_recognizer = PatternRecognizer(supported_entity="NUMBER", patterns=[pattern_numbers])
aadhaar_recognizer = PatternRecognizer(supported_entity="AADHAAR_NUMBER", patterns=[pattern_aadhaar])
voter_id_recognizer = PatternRecognizer(supported_entity="VOTER_ID", patterns=[pattern_voter_id])
pan_card_recognizer = PatternRecognizer(supported_entity="PAN_CARD", patterns=[pattern_pan_card])
credit_card_recognizer = PatternRecognizer(supported_entity="CREDIT_CARD", patterns=[pattern_credit_card])
bank_account_recognizer = PatternRecognizer(supported_entity="BANK_ACCOUNT", patterns=[pattern_bank_account])
driver_license_recognizer = PatternRecognizer(supported_entity="DRIVER_LICENSE", patterns=[pattern_driver_license])
email_recognizer = PatternRecognizer(supported_entity="EMAIL", patterns=[pattern_email])
ssn_recognizer = PatternRecognizer(supported_entity="SSN", patterns=[pattern_ssn])
ip_recognizer = PatternRecognizer(supported_entity="IP", patterns=[pattern_ip])
date_recognizer = PatternRecognizer(supported_entity="DATE", patterns=[pattern_date])
passport_recognizer = PatternRecognizer(supported_entity="PASSPORT", patterns=[pattern_passport])
phone_number_recognizer = PatternRecognizer(supported_entity="PHONE_NUMBER", patterns=[pattern_phone_number])
upi_id_recognizer = PatternRecognizer(supported_entity="UPI_ID", patterns=[pattern_upi_id])


analyzer = AnalyzerEngine()

analyzer.registry.add_recognizer(random_recognizer)
# analyzer.registry.add_recognizer(pii_entity_recognizer)
analyzer.registry.add_recognizer(number_recognizer)
analyzer.registry.add_recognizer(aadhaar_recognizer)
analyzer.registry.add_recognizer(voter_id_recognizer)
analyzer.registry.add_recognizer(pan_card_recognizer)
analyzer.registry.add_recognizer(credit_card_recognizer)
analyzer.registry.add_recognizer(bank_account_recognizer)
analyzer.registry.add_recognizer(driver_license_recognizer)
analyzer.registry.add_recognizer(email_recognizer)
analyzer.registry.add_recognizer(ssn_recognizer)
analyzer.registry.add_recognizer(ip_recognizer)
analyzer.registry.add_recognizer(date_recognizer)
analyzer.registry.add_recognizer(passport_recognizer)
analyzer.registry.add_recognizer(phone_number_recognizer)
analyzer.registry.add_recognizer(upi_id_recognizer)


def pseudonymize_data(json_data, denial_list):
    pseudonymized_data = []
    mapping = {}

    for key, value in json_data.items():
        if key not in denial_list:
            results = analyzer.analyze(str(value),language='en')
            if results:
                pseudonym = f"PII_{len(mapping) + 1}"
                mapping[value] = pseudonym
                json_data[key] = pseudonym
            else:
                json_data[key] = value

    pseudonymized_data.append(json_data)

    return pseudonymized_data, mapping


# # Example JSON input
# input_json_2 = '''
# {
#   "Name": "Emily Brown",
#   "Email": "emily.brown@example.com",
#   "Phone": "+1 (555) 456-7890",
#   "Address": "321 Pine St",
#   "CreditCard": "9876543210987654",
#   "SSN": "321-54-9876",
#   "DriverLicense": "DL54321098765432",
#   "Passport": "P4321567",
#   "BankAccount": "1098765432",
#   "UPI_ID": "emily.brown@upi",
#   "Age": 33,
#   "Gender": "Female",
#   "Nationality": "AU",
#   "Employment": "Employed",
#   "Salary": 60000,
#   "Company": "XYZ Corp",
#   "MedicalRecord": "MR654321",
#   "HealthInsurance": "54321",
#   "Username": "emilybrown",
#   "Password": "pa$$w0rd",
#   "Website": "www.example.co",
#   "ProductCode": "WXYZ8765",
#   "TrackingNumber": "T543210987",
#   "SocialMedia": "@emilybrown",
#   "FavoriteColor": "Purple",
#   "DateOfBirth": "1990-07-10",
#   "FavoriteFood": "Pasta",
#   "TravelDocument": "T43210987",
#   "MemberID": "M654321",
#   "DeviceSerialNumber": "SN0987654321",
#   "TransactionID": "TXN543210",
#   "IncomeTaxID": "IT98765",
#   "UserIdentifier": "UID98765",
#   "VehiclePlateNumber": "QWE543",
#   "LibraryCardNumber": "LC65432",
#   "CustomerID": "CUST543",
#   "SubscriptionID": "SUBS543",
#   "PostalCode": "56789",
#   "EmergencyContact": "+1 (555) 789-0123",
#   "FavoriteSport": "Baseball",
#   "FavoriteMovie": "The Godfather",
#   "RandomData1": "PQR321",
#   "RandomData2": "LMN987",
#   "RandomData3": "XYZ654",
#   "RandomData4": "321CBA",
#   "RandomData5": "987LMN"
# }
# '''

# # Convert JSON string to dictionary
# json_data = json.loads(input_json_2)

# # List of keys to deny pseudonymization
# denial_list = []

# # Perform pseudonymization
# pseudonymized_data, mapping = pseudonymize_data(json_data, denial_list)

# # Print pseudonymized data
# print("Pseudonymized Data:")
# for row in pseudonymized_data:
#     print(json.dumps(row, indent=2))

# # Print mapping
# print("Mapping:")
# for value, key in mapping.items():
#     print(f"- {value}: {key}")