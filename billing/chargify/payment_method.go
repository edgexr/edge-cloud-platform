package chargify

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/mobiledgex/edge-cloud-infra/billing"
	"github.com/mobiledgex/edge-cloud-infra/infracommon"
)

func addPayment(id int, payment *billing.PaymentMethod) (int, error) {
	switch payment.PaymentType {
	case "":
		return 0, fmt.Errorf("no payment methods specified")
	case billing.PAYMENT_TYPE_CC:
		newProfile := PaymentProfile{
			PaymentType:     paymentTypeCC,
			CustomerId:      id,
			FirstName:       payment.CreditCard.FirstName,
			LastName:        payment.CreditCard.LastName,
			FullNumber:      payment.CreditCard.CardNumber,
			CardType:        payment.CreditCard.CardType,
			ExpirationMonth: payment.CreditCard.ExpirationMonth,
			ExpirationYear:  payment.CreditCard.ExpirationYear,
			Cvv:             payment.CreditCard.Cvv,
			BillingAddress:  payment.CreditCard.BillingAddress,
			BillingAddress2: payment.CreditCard.BillingAddress2,
			BillingCity:     payment.CreditCard.City,
			BillingState:    payment.CreditCard.State,
			BillingZip:      payment.CreditCard.Zip,
			BillingCountry:  payment.CreditCard.Country,
		}
		endpoint := "/payment_profiles.json"
		resp, err := newChargifyReq("POST", endpoint, PaymentProfileWrapper{PaymentProfile: &newProfile})
		if err != nil {
			return 0, err
		}
		if resp.StatusCode == http.StatusCreated {
			payResp := PaymentProfileWrapper{}
			err = json.NewDecoder(resp.Body).Decode(&payResp)
			if err != nil {
				return 0, fmt.Errorf("Error parsing response: %v\n", err)
			}
			return payResp.PaymentProfile.Id, nil
		}
		defer resp.Body.Close()
		return 0, infracommon.GetReqErr(resp.Body)
	default:
		return 0, fmt.Errorf("unknown payment type: %s", payment.PaymentType)
	}
}
