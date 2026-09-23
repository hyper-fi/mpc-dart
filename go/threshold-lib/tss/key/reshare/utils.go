package reshare

import (
	"fmt"
	"github.com/okx/threshold-lib/tss"
)

func RefreshEcdsaKeyShares(share1st string, share2nd string) ([]string, error) {
	var refresh1 *RefreshInfo = nil
	var refresh2 *RefreshInfo = nil
	var refresh3 *RefreshInfo = nil

	data1st := &tss.KeyStep3Data{}
	err := data1st.UnmarshalJSON([]byte(share1st), "ecdsa")
	if err != nil {
		return nil, err
	}
	if data1st.Id < 1 || data1st.Id > 3 {
		return nil, fmt.Errorf("invalid data1st.Id")
	}

	data2nd := &tss.KeyStep3Data{}
	err = data2nd.UnmarshalJSON([]byte(share2nd), "ecdsa")
	if err != nil {
		return nil, err
	}
	if data2nd.Id < 1 || data2nd.Id > 3 {
		return nil, fmt.Errorf("invalid data2nd.Id")
	}

	if data1st.Id == data2nd.Id {
		return nil, fmt.Errorf("data1st.Id == data2nd.Id")
	}
	if !data1st.PublicKey.Equals(data2nd.PublicKey) {
		return nil, fmt.Errorf("data1st.PublicKey != data2nd.PublicKey")
	}

	devoteList := [2]int{data1st.Id, data2nd.Id}

	if data1st.Id == 1 || data2nd.Id == 1 {
		if data1st.Id == 1 {
			refresh1 = NewRefresh(1, 3, devoteList, data1st.ShareI, data1st.PublicKey)
		} else {
			refresh1 = NewRefresh(1, 3, devoteList, data2nd.ShareI, data1st.PublicKey)
		}
	} else {
		refresh1 = NewRefresh(1, 3, devoteList, nil, data1st.PublicKey)
	}

	if data1st.Id == 2 || data2nd.Id == 2 {
		if data1st.Id == 2 {
			refresh2 = NewRefresh(2, 3, devoteList, data1st.ShareI, data1st.PublicKey)
		} else {
			refresh2 = NewRefresh(2, 3, devoteList, data2nd.ShareI, data1st.PublicKey)
		}
	} else {
		refresh2 = NewRefresh(2, 3, devoteList, nil, data1st.PublicKey)
	}

	if data1st.Id == 3 || data2nd.Id == 3 {
		if data1st.Id == 3 {
			refresh3 = NewRefresh(3, 3, devoteList, data1st.ShareI, data1st.PublicKey)
		} else {
			refresh3 = NewRefresh(3, 3, devoteList, data2nd.ShareI, data1st.PublicKey)
		}
	} else {
		refresh3 = NewRefresh(3, 3, devoteList, nil, data1st.PublicKey)
	}

	msgs1_1, _ := refresh1.DKGStep1()
	msgs2_1, _ := refresh2.DKGStep1()
	msgs3_1, _ := refresh3.DKGStep1()

	msgs1_2_in := []*tss.Message{msgs2_1[1], msgs3_1[1]}
	msgs2_2_in := []*tss.Message{msgs1_1[2], msgs3_1[2]}
	msgs3_2_in := []*tss.Message{msgs1_1[3], msgs2_1[3]}

	msgs1_2, _ := refresh1.DKGStep2(msgs1_2_in)
	msgs2_2, _ := refresh2.DKGStep2(msgs2_2_in)
	msgs3_2, _ := refresh3.DKGStep2(msgs3_2_in)

	msgs1_3_in := []*tss.Message{msgs2_2[1], msgs3_2[1]}
	msgs2_3_in := []*tss.Message{msgs1_2[2], msgs3_2[2]}
	msgs3_3_in := []*tss.Message{msgs1_2[3], msgs2_2[3]}

	p1SaveData, _ := refresh1.DKGStep3(msgs1_3_in)
	p2SaveData, _ := refresh2.DKGStep3(msgs2_3_in)
	p3SaveData, _ := refresh3.DKGStep3(msgs3_3_in)

	// update ChainCode
	p1SaveData.ChainCode = data1st.ChainCode
	p2SaveData.ChainCode = data1st.ChainCode
	p3SaveData.ChainCode = data1st.ChainCode

	p1JsonData, _ := p1SaveData.MarshalJSON("ecdsa")
	p2JsonData, _ := p2SaveData.MarshalJSON("ecdsa")
	p3JsonData, _ := p3SaveData.MarshalJSON("ecdsa")
	return []string{
		string(p1JsonData),
		string(p2JsonData),
		string(p3JsonData),
	}, nil
}
