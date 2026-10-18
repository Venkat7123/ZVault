"""Synthetic bank data: customers, transactions, chats and agent notes.

All people, accounts and numbers are invented. Each chat carries an intent and the
retention class a bank would apply to it, which is the training label for Feature 2:

    short       30 days   routine questions with no ongoing purpose
    service     1 year    service requests (card block, address change, complaints)
    regulatory  5 years   disputes, fraud reports, KYC (RBI / PMLA record keeping)
    contract    20 years  loan applications (kept for the loan term)

Every intent has several phrasing templates, split into "train" and "test" families,
so the retention model is evaluated on phrasings it never saw during training.
"""

import random
from dataclasses import dataclass, field

RETENTION_DAYS = {"short": 30, "service": 365, "regulatory": 5 * 365, "contract": 20 * 365}

# Generic placeholder names only (team rule: no real-looking personal names).
FIRST = ["Alpha", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot", "Golf", "Hotel", "Juliet", "Kilo",
         "Lima", "Mike", "Nova", "Oscar", "Papa", "Quebec", "Romeo", "Sierra", "Tango", "Victor"]
LAST = [f"Holder{n:02d}" for n in range(1, 16)]
CITIES = ["Mumbai", "Chennai", "Hyderabad", "Bengaluru", "Pune", "Kolkata", "Delhi", "Kochi", "Jaipur", "Lucknow"]
MERCHANTS = ["QuickMart", "FuelPoint", "TrainTix", "MediPlus Pharmacy", "UrbanEats", "BookNest",
             "GadgetHub", "Metro Electricity", "SkyFly Travels", "StyleStreet"]
CHANNELS = ["UPI", "debit card", "credit card", "NEFT", "IMPS"]

# intent -> (retention class, train templates, test templates)
INTENTS = {
    "balance_check": ("short", [
        "What is my account balance?",
        "Can you tell me how much money is in my savings account?",
        "Show my balance please.",
        "mera balance kitna hai?",
    ], [
        "How much do I currently have in my account ending {acct4}?",
        "balance batao please",
    ]),
    "general_query": ("short", [
        "What are the branch timings in {city}?",
        "What is the current fixed deposit interest rate?",
        "Is the bank open on Saturday?",
    ], [
        "Which documents do I need to open a recurring deposit?",
        "What time does the {city} branch close today?",
    ]),
    "card_block": ("service", [
        "Please block my debit card, I lost it in {city}.",
        "My credit card was stolen, block it immediately.",
        "card kho gaya hai, block kar do.",
    ], [
        "I cannot find my card since yesterday, please freeze it.",
        "Someone took my wallet with the debit card, stop the card now.",
    ]),
    "address_change": ("service", [
        "I want to change my address to {city}.",
        "Please update my communication address, I moved to {city}.",
    ], [
        "Kindly record my new residential address in {city}.",
    ]),
    "complaint": ("service", [
        "The ATM in {city} did not dispense cash but my account was debited Rs {amount}.",
        "I am unhappy with the service at the {city} branch.",
    ], [
        "Cash was not given by the machine yet Rs {amount} was deducted.",
    ]),
    "dispute": ("regulatory", [
        "I dispute the {channel} transaction of Rs {amount} to {merchant} on {date}.",
        "I did not make the payment of Rs {amount} at {merchant}, please investigate.",
        "There is a wrong charge of Rs {amount} from {merchant} on my {channel}.",
    ], [
        "Rs {amount} went to {merchant} on {date} and I never authorised it.",
        "Please raise a chargeback for the {merchant} payment of Rs {amount}.",
    ]),
    "fraud_report": ("regulatory", [
        "Someone called pretending to be from the bank and I shared my OTP. Rs {amount} is gone.",
        "I got a fake KYC update link and money was taken from my account.",
        "A caller said I was under digital arrest and made me transfer Rs {amount}.",
    ], [
        "I was tricked by a fake police officer on video call into sending Rs {amount}.",
        "My account was emptied after I clicked an SMS link about my electricity bill.",
    ]),
    "kyc_update": ("regulatory", [
        "I want to update my KYC, my PAN is {pan}.",
        "Please link my Aadhaar to my account.",
    ], [
        "Here is my PAN {pan} for re-KYC.",
    ]),
    "loan_application": ("contract", [
        "I want to apply for a home loan of {lakh} lakh for {years} years.",
        "Please start my car loan application of {lakh} lakh.",
        "I need a personal loan of {lakh} lakh repayable over {years} years.",
    ], [
        "Can I get a {years} year housing loan of {lakh} lakh in {city}?",
        "I would like to borrow {lakh} lakh to buy a flat, tenure {years} years.",
    ]),
}

# agent notes written by the analyst AI after a dispute or fraud report
NOTE_TEMPLATES = [
    "Case note: customer reports unauthorised {channel} debit of Rs {amount} to {merchant}. Velocity check flagged 3 payments in 10 minutes.",
    "Case note: customer {name} disputes Rs {amount}. Device fingerprint differs from the last 90 days.",
    "Case note: possible social engineering. Customer shared OTP. Beneficiary account opened 2 days ago.",
]


@dataclass
class Customer:
    customer_id: str
    name: str
    city: str
    account_no: str
    pan: str
    phone: str

    def identifiers(self) -> list[str]:
        """Values that must never be recoverable after erasure (the recovery test's canaries)."""
        return [self.name, self.account_no, self.pan, self.phone]


@dataclass
class Message:
    customer_id: str
    kind: str          # "chat", "agent-memory" or "transaction"
    text: str
    intent: str
    retention: str     # label for Feature 2
    family: str        # "train" or "test" phrasing family
    days_ago: int


@dataclass
class Bank:
    customers: list[Customer]
    messages: list[Message] = field(default_factory=list)

    def for_customer(self, customer_id: str) -> list[Message]:
        return [m for m in self.messages if m.customer_id == customer_id]


def _fill(template: str, rng: random.Random, c: Customer) -> str:
    return template.format(
        city=rng.choice(CITIES), amount=f"{rng.randint(5, 950) * 100:,}", merchant=rng.choice(MERCHANTS),
        channel=rng.choice(CHANNELS), date=f"{rng.randint(1, 28)} {rng.choice(['Aug', 'Sep', 'Oct'])}",
        pan=c.pan, acct4=c.account_no[-4:], lakh=rng.choice([5, 8, 12, 25, 40, 50, 75]),
        years=rng.choice([3, 5, 7, 15, 20, 25]), name=c.name,
    )


def make_customer(rng: random.Random, index: int, prefix: str = "CUST") -> Customer:
    return Customer(
        customer_id=f"{prefix}-{index:04d}",
        name=f"{rng.choice(FIRST)} {rng.choice(LAST)}",
        city=rng.choice(CITIES),
        account_no=f"{rng.randint(10**11, 10**12 - 1)}",
        pan="".join(rng.choice("ABCDEFGHJKLMNPQRSTUVWXYZ") for _ in range(5)) + f"{rng.randint(1000, 9999)}"
            + rng.choice("ABCDEFGHJKLMNPQRSTUVWXYZ"),
        phone=f"9{rng.randint(10**8, 10**9 - 1)}",
    )


def generate_bank(n_customers: int = 60, seed: int = 7, prefix: str = "CUST") -> Bank:
    rng = random.Random(seed)
    bank = Bank([make_customer(rng, i + 1, prefix) for i in range(n_customers)])
    intents = list(INTENTS)
    for c in bank.customers:
        for _ in range(rng.randint(4, 8)):
            intent = rng.choice(intents)
            label, train, test = INTENTS[intent]
            family = "test" if rng.random() < 0.3 else "train"
            template = rng.choice(test if family == "test" else train)
            bank.messages.append(Message(c.customer_id, "chat", _fill(template, rng, c), intent, label, family,
                                         rng.randint(0, 400)))
            if intent in ("dispute", "fraud_report"):
                note = _fill(rng.choice(NOTE_TEMPLATES), rng, c)
                bank.messages.append(Message(c.customer_id, "agent-memory", note, intent, "regulatory", family,
                                             rng.randint(0, 400)))
        for _ in range(rng.randint(2, 4)):
            text = (f"Transaction: {rng.choice(CHANNELS)} payment of Rs {rng.randint(1, 900) * 100:,} to "
                    f"{rng.choice(MERCHANTS)} from account {c.account_no} on {rng.randint(1, 28)} Oct.")
            bank.messages.append(Message(c.customer_id, "transaction", text, "transaction", "regulatory", "train",
                                         rng.randint(0, 400)))
    return bank
