# Synthetic fixture: Acme Zorblax invoicing helpers. Everything here is made up.


class AcmeInvoice:
    def __init__(self, lines):
        self.lines = lines

    def acme_total(self, tax_rate):
        subtotal = sum(qty * price for qty, price in self.lines)
        return round(subtotal * (1 + tax_rate), 2)


def zorblax_discount(total, percent):
    if percent < 0 or percent > 100:
        raise ValueError("percent out of range")
    return round(total * (100 - percent) / 100, 2)
