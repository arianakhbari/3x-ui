package service

import (
    "x-ui/database"
    "x-ui/database/model"
    "x-ui/logger"
    "x-ui/xray"

    "gorm.io/gorm"
)

type OutboundService struct{}

func (s *OutboundService) AddTraffic(traffics []*xray.Traffic, clientTraffics []*xray.ClientTraffic) error {
    var err error
    db := database.GetDB()
    tx := db.Begin()

    defer func() {
        if err != nil {
            tx.Rollback()
        } else {
            tx.Commit()
        }
    }()

    err = s.addOutboundTraffic(tx, traffics)
    if err != nil {
        return err
    }

    // If needed, process clientTraffics here

    return nil
}

func (s *OutboundService) addOutboundTraffic(tx *gorm.DB, traffics []*xray.Traffic) error {
    if len(traffics) == 0 {
        return nil
    }

    for _, traffic := range traffics {
        if traffic.IsOutbound {
            err := tx.Model(&model.OutboundTraffics{}).
                Where("tag = ?", traffic.Tag).
                Updates(map[string]interface{}{
                    "tag":   traffic.Tag,
                    "up":    gorm.Expr("up + ?", traffic.Up),
                    "down":  gorm.Expr("down + ?", traffic.Down),
                    "total": gorm.Expr("total + ? + ?", traffic.Up, traffic.Down),
                }).Error
            if err != nil {
                logger.Error("Failed to update outbound traffic: ", err)
                return err
            }
        }
    }
    return nil
}

func (s *OutboundService) GetOutboundsTraffic() ([]*model.OutboundTraffics, error) {
    db := database.GetDB()
    var traffics []*model.OutboundTraffics

    err := db.Model(&model.OutboundTraffics{}).Find(&traffics).Error
    if err != nil {
        logger.Warning("Error retrieving OutboundTraffics: ", err)
        return nil, err
    }

    return traffics, nil
}

func (s *OutboundService) ResetOutboundTraffic(tag string) error {
    db := database.GetDB()
    var err error

    if tag == "-alltags-" {
        err = db.Model(&model.OutboundTraffics{}).
            Updates(map[string]interface{}{"up": 0, "down": 0, "total": 0}).Error
    } else {
        err = db.Model(&model.OutboundTraffics{}).
            Where("tag = ?", tag).
            Updates(map[string]interface{}{"up": 0, "down": 0, "total": 0}).Error
    }
    if err != nil {
        logger.Error("Failed to reset outbound traffic: ", err)
        return err
    }
    return nil
}
