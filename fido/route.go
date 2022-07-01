package fido

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/etda-uaf/uaf-server/app"
	db "github.com/etda-uaf/uaf-server/db/model"
	"github.com/etda-uaf/uaf-server/fido/model"
	"github.com/etda-uaf/uaf-server/fido/op"
	"github.com/etda-uaf/uaf-server/fido/status"
	"github.com/etda-uaf/uaf-server/utils"
	"github.com/gin-gonic/gin"
	"github.com/thedevsaddam/gojsonq/v2"
)

type GetContext struct {
	Username    string
	Transaction string
}

func checkQrCodeToken(c *gin.Context) {

	fmt.Println("[info] ---------- Start Check QrCode Token Session() ----------")

	var uafRequest model.GetUAFRequest
	err := c.BindJSON(&uafRequest)
	if err != nil {
		fmt.Println("[error] " + err.Error())
		c.JSON(http.StatusBadRequest, model.UAFResponse(model.OperationUnknown, status.BadRequest, nil, err))
		return
	}

	if !app.Config.ConformanceMode {
		if uafRequest.QrCodeToken == nil {
			fmt.Println("[error] " + status.ErrInvalidQrCode.Error())
			c.JSON(http.StatusBadRequest, model.UAFResponse(model.OperationUnknown, status.BadRequest, nil, status.ErrInvalidQrCode))
			c.Abort()
			return
		}
		qrCode, err := op.ValidateQrCodeToken(*uafRequest.QrCodeToken)
		if err != nil || qrCode == nil {
			fmt.Println("[error] " + status.ErrInvalidQrCode.Error())
			c.JSON(http.StatusBadRequest, model.UAFResponse(model.OperationUnknown, status.BadRequest, nil, status.ErrInvalidQrCode))
			c.Abort()
			return
		}

		if qrCode.Status == db.QR_CODE_STATUS_EXPIRED || qrCode.Status == db.QR_CODE_STATUS_USED {
			fmt.Println("[error] " + status.ErrQrCodeExpired.Error())
			c.JSON(http.StatusBadRequest, model.UAFResponse(model.OperationUnknown, status.BadRequest, nil, status.ErrQrCodeExpired))
			c.Abort()
			return
		}
	}

	var getContext GetContext
	json.Unmarshal([]byte(*uafRequest.Context), &getContext)

	//Must disable in PRD
	//getContext.Username = "kod@etda.or.th"

	//Get Account_Id
	account := db.FindAccountByIdentity(getContext.Username)
	if account == nil {
		fmt.Println("[error] " + status.ErrInvalidIdentity.Error())
		c.JSON(http.StatusBadRequest, model.UAFResponse(model.OperationUnknown, status.BadRequest, nil, status.ErrInvalidIdentity))
		c.Abort()
		return
	}

	//Get QRCode
	qrCode, err := op.ValidateQrCodeToken(*uafRequest.QrCodeToken)
	if err != nil || qrCode == nil {
		fmt.Println("[error] " + err.Error())
		c.JSON(http.StatusBadRequest, model.UAFResponse(model.OperationUnknown, status.BadRequest, nil, status.ErrInvalidQrCode))
		c.Abort()
		return
	}

	//Update Account ID to QRCode
	qrCode.AccountID = account.ID
	if err := app.Db.Model(&db.QrCode{}).Where("id = ?", qrCode.ID).Update("account_id", account.ID).Error; err != nil {
		fmt.Println("[error] " + err.Error())
		c.JSON(http.StatusBadRequest, model.UAFResponse(model.OperationUnknown, status.BadRequest, nil, status.ErrUpdateAccountID))
		c.Abort()
		return
	}

	c.Set("qrCode", qrCode)
	c.Set("uafRequest", uafRequest)
	c.Next()

}

func InitRoute(e *gin.RouterGroup) {
	e.POST("/get", checkQrCodeToken, PostRequest)
	e.POST("/respond", PostResponse)
	e.GET("/", Facet)
}

func Facet(c *gin.Context) {

	TrustedFacetList := model.UAFGetTrustedFacetIdsResponse{TrustedFacets: app.Config.TrustedFacets}
	c.JSON(http.StatusOK, TrustedFacetList)
}

func PostRequest(c *gin.Context) {

	r, _ := c.Get("uafRequest")
	uafRequest := r.(model.GetUAFRequest)

	var qrCode *db.QrCode

	if !app.Config.ConformanceMode {
		q, qrExisted := c.Get("qrCode")
		if !qrExisted {
			c.JSON(http.StatusBadRequest, model.UAFResponse(model.OperationReg, status.BadRequest, nil, errors.New("invalid qrcode")))
			return
		}
		qrCode = q.(*db.QrCode)
	}

	switch uafRequest.Op {
	case model.OperationReg:
		var regContext model.RegistrationContext
		err := utils.Unmarshal(uafRequest.Context, &regContext)
		if err != nil {
			fmt.Println("[error] " + err.Error())
			c.JSON(http.StatusBadRequest, model.UAFResponse(model.OperationReg, status.BadRequest, nil, err))
			return
		}

		regRequest, stat, err := op.GetReg(&regContext, qrCode)
		if stat != status.Ok {
			fmt.Println("[error] " + err.Error())
			c.JSON(http.StatusBadRequest, model.UAFResponse(model.OperationReg, stat, nil, err))
			return
		}
		reqs := make([]interface{}, 1)
		reqs[0] = *regRequest
		c.JSON(http.StatusOK, model.UAFResponse(model.OperationReg, stat, reqs, nil))

	case model.OperationAuth:
		var authContext model.AuthenticationContext
		err := utils.Unmarshal(uafRequest.Context, &authContext)
		if err != nil {
			fmt.Println("[error] " + err.Error())
			c.JSON(http.StatusBadRequest, model.UAFResponse(model.OperationAuth, status.BadRequest, nil, err))
			return
		}

		authRequest, stat, err := op.GetAuth(&authContext, qrCode)
		if stat != status.Ok {
			fmt.Println("[error] " + err.Error())
			c.JSON(http.StatusBadRequest, model.UAFResponse(model.OperationAuth, stat, nil, err))
			return
		}
		reqs := make([]interface{}, 1)
		reqs[0] = *authRequest
		c.JSON(http.StatusOK, model.UAFResponse(model.OperationAuth, stat, reqs, nil))

	case model.OperationDereg:
		var deregContext model.DeregistrationContext
		err := utils.Unmarshal(uafRequest.Context, &deregContext)
		if err != nil {
			fmt.Println("[error] " + err.Error())
			c.JSON(http.StatusBadRequest, model.UAFResponse(model.OperationDereg, status.BadRequest, nil, err))
			return
		}

		deregRequest, stat, err := op.GetDereg(&deregContext)
		if stat != status.Ok {
			fmt.Println("[error] " + err.Error())
			c.JSON(http.StatusBadRequest, model.UAFResponse(model.OperationDereg, stat, nil, err))
			return
		}
		reqs := make([]interface{}, 1)
		reqs[0] = *deregRequest
		c.JSON(http.StatusOK, model.UAFResponse(model.OperationDereg, stat, reqs, nil))

	default:
		fmt.Println("[error] " + status.ErrInvalidOperation.Error())
		c.JSON(http.StatusBadRequest, model.UAFResponse(model.OperationUnknown, status.BadRequest, nil, status.ErrInvalidOperation))
		return
	}
}

func PostResponse(c *gin.Context) {
	var uafResponse model.SendUAFResponse
	err := c.BindJSON(&uafResponse)
	if err != nil {
		fmt.Println("[error] " + err.Error())
		c.JSON(http.StatusBadRequest, model.UAFResponse(model.OperationUnknown, status.BadRequest, nil, err))
		return
	}

	jq := gojsonq.New().FromString(*uafResponse.UafResponse)
	if jq.Error() != nil {
		c.JSON(http.StatusBadRequest, model.UAFResponse(model.OperationUnknown, status.BadRequest, nil, jq.Error()))
		return
	}

	opcode := jq.Find("[0].header.op")
	switch opcode {
	case string(model.OperationReg):
		var regResponse model.RegistrationResponse

		jq.Reset().From("[0]").Out(&regResponse)

		if jq.Error() != nil {
			c.JSON(http.StatusOK, model.UAFResponse(model.OperationReg, status.UnacceptableContent, nil, err))
			return
		}

		stat, err := op.PostReg(&regResponse)
		if stat != status.Ok {
			fmt.Println("[error] " + err.Error())
			c.JSON(http.StatusOK, model.UAFResponse(model.OperationReg, stat, nil, err))
			return
		}
		c.JSON(http.StatusOK, model.UAFResponse(model.OperationReg, stat, nil, nil))

	case string(model.OperationAuth):
		var authResponse model.AuthenticationResponse

		jq.Reset().From("[0]").Out(&authResponse)

		if jq.Error() != nil {
			c.JSON(http.StatusOK, model.UAFResponse(model.OperationAuth, status.UnacceptableContent, nil, err))
			return
		}

		stat, err := op.PostAuth(&authResponse)
		if stat != status.Ok {
			fmt.Println("[error] " + err.Error())
			c.JSON(http.StatusOK, model.UAFResponse(model.OperationAuth, stat, nil, err))
			return
		}
		c.JSON(http.StatusOK, model.UAFResponse(model.OperationAuth, stat, nil, nil))

	case string(model.OperationDereg):
		// De-registration request should not be received here
		// This block is implemented for conformance purpose
		c.JSON(http.StatusOK, model.UAFResponse(model.OperationDereg, status.UnacceptableContent, nil, err))
		return

	case nil:
		fmt.Println("[error] " + status.ErrInvalidOperation.Error())
		c.JSON(http.StatusOK, model.UAFResponse(model.OperationUnknown, status.UnacceptableContent, nil, status.ErrInvalidOperation))
		return
	default:
		fmt.Println("[error] " + status.ErrInvalidOperation.Error())
		c.JSON(http.StatusOK, model.UAFResponse(model.OperationUnknown, status.UnacceptableContent, nil, status.ErrInvalidOperation))
		return
	}

}
