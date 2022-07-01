package validator

import (
	"crypto/sha256"
	"errors"
	"github.com/etda-uaf/uaf-server/app"
	db "github.com/etda-uaf/uaf-server/db/model"
	"github.com/etda-uaf/uaf-server/fido/model"
	"github.com/etda-uaf/uaf-server/fido/status"
	"github.com/etda-uaf/uaf-server/utils"
	"github.com/google/uuid"
)

var (
	ErrUntrustedFacet   = errors.New("untrusted facet")
	ErrSessionExpired   = errors.New("session expired")
	ErrInvalidParameter = errors.New("invalid parameters")
)

func ValidateResponse(fcParams string, header model.OperationHeader) (*db.Session, []byte, status.Status, error) {
	var fcp model.FinalChallengeParams
	err := utils.Base64Decode(fcParams, &fcp)

	if err != nil {
		return nil, nil, status.UnacceptableContent, err
	}
	fcpHash := sha256.Sum256([]byte(fcParams))

	token, err := utils.ValidateJwtToken(*header.ServerData, &utils.ServerDataClaim{})
	if err != nil {
		return nil, nil, status.Forbidden, err
	}

	serverData := token.Claims.(*utils.ServerDataClaim).Data

	sessionId, err := uuid.Parse(serverData.Id)
	if err != nil {
		return nil, nil, status.BadRequest, ErrSessionExpired
	}
	session := db.FindSessionById(sessionId.String())
	if session == nil {
		return nil, nil, status.RequestInvalid, ErrSessionExpired
	}

	if session.Challenge != fcp.Challenge ||
		session.Challenge != serverData.Challenge {
		return nil, nil, status.RequestInvalid, ErrInvalidParameter
	}
	if ValidateTrustedFacets(fcp.FacetID, header.Upv) != nil || ValidateTrustedFacets(fcp.AppID, header.Upv) != nil {
		return nil, nil, status.Forbidden, ErrUntrustedFacet
	}

	return session, fcpHash[:], status.Ok, nil
}

func ValidateTrustedFacets(facetId string, version model.Version) error {
	for _, tf := range app.Config.TrustedFacets {
		if utils.Contains(tf.Ids, facetId) {
			if tf.Version == version {
				return nil
			}
		}
	}
	return ErrUntrustedFacet
}
