package main

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"log"
	"net/http"
	"strconv"
	"time"
)

type User struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	DeletedAt time.Time `json:"deleted_at" gorm:"index"`
	Username  string    `json:"username" gorm:"uniqueIndex"`
	Password  string    `json:"password"`
	Email     string    `json:"email" gorm:"uniqueIndex"`
}

type Temperature struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	DeletedAt   time.Time `json:"deleted_at" gorm:"index"`
	Time        string    `json:"time" gorm:"index"`
	Temperature string    `json:"temperature"`
	Electricity string    `json:"electricity"`
	DeviceID    string    `json:"device_id" gorm:"index"`
}
type resultData struct {
	Time        string `json:"time" gorm:"index"`
	Temperature string `json:"temperature"`
	DeviceID    string `json:"device_id" gorm:"index"`
}
type Location struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	DeletedAt time.Time `json:"deleted_at" gorm:"index"`
	Time      string    `json:"time" gorm:"index"`
	Lat       string    `json:"lat"`
	Lon       string    `json:"lon"`
	DeviceID  string    `json:"device_id" gorm:"index"`
}

type MqttConfig struct {
	Broker   string `json:"broker"`
	Username string `json:"username"`
	Password string `json:"password"`
	Topic1   string `json:"topic1"`
	Topic2   string `json:"topic2"`
}

var db *gorm.DB

func main() {
	dsn := "test:test@tcp(127.0.0.1:3306)/app-test?charset=utf8mb4&parseTime=True&loc=Local&sql_mode=STRICT_ALL_TABLES"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("Failed to connect to database")
	}

	db.AutoMigrate(&User{}, &Temperature{}, &Location{})

	r := gin.Default()
	r.Use(cors.Default())
	auth := r.Group("/auth")
	{
		auth.POST("/register", func(c *gin.Context) {
			var user User
			if err := c.ShouldBindJSON(&user); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
				return
			}

			user.Password = string(hashedPassword)
			result := db.Create(&user)
			if result.Error != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "User registered successfully"})
		})
		auth.GET("/api/getLatestData", func(c *gin.Context) {
			data, err := getLatestData(c, db)
			if err != nil {
				// 处理错误
			}
			c.JSON(http.StatusOK, data)
		})

		auth.POST("/api/getTemperatureResult", func(c *gin.Context) {
			var TemperatureData struct {
				Startime int64  `json:"star_time"`
				Endtime  int64  `json:"end_time"`
				DeviceID string `json:"device_id"`
			}
			if err := c.ShouldBindJSON(&TemperatureData); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			data, _ := getTemperatureResult(db, TemperatureData.DeviceID, TemperatureData.Startime, TemperatureData.Endtime)
			c.JSON(http.StatusOK, data)
		})
		auth.POST("/api/setMessage", func(c *gin.Context) {
			var setMessageData struct {
				DeviceID    string `json:"device_id"`
				Rate        int64  `json:"rate"`
				Difference  string `json:"difference"`
				Threshold   string `json:"threshold"`
				Phonenotice string `json:"phone_notice"`
				Msgnotice   string `json:"msg_notice"`
			}
			if err := c.ShouldBindJSON(&setMessageData); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				log.Print("1111")
				return
			}
			setMessageNotice(db, c, setMessageData)
			var Reslut struct {
				Code    int64  `json:"code"`
				Message string `json:"message"`
			}
			log.Println(setMessageData)
			Reslut.Code = 200
			Reslut.Message = "成功"
			c.JSON(http.StatusOK, Reslut)
		})
		auth.POST("/api/getTemperatureAll", func(c *gin.Context) {
			var TemperatureData struct {
				Startime int64  `json:"star_time"`
				Endtime  int64  `json:"end_time"`
				DeviceID string `json:"device_id"`
			}
			if err := c.ShouldBindJSON(&TemperatureData); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			data, _ := getTemperatureByDeviceID(db, c, TemperatureData.DeviceID, TemperatureData.Startime, TemperatureData.Endtime)
			c.JSON(http.StatusOK, data)
		})
		auth.POST("/login", func(c *gin.Context) {
			var loginData struct {
				Username string `json:"username"`
				Password string `json:"password"`
			}
			if err := c.ShouldBindJSON(&loginData); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			var user User
			result := db.Where("username = ?", loginData.Username).First(&user)
			if result.Error != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
				return
			}

			err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginData.Password))
			if err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
				return
			}

			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"username": user.Username,
				"exp":      time.Now().Add(time.Hour * 24).Unix(),
			})

			tokenString, err := token.SignedString([]byte("your-secret-key"))
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"token": tokenString})
		})
	}

	mqttConfig := MqttConfig{
		Broker:   "127.0.0.1:1883",
		Username: "",
		Password: "",
		Topic1:   "/qos0topic1",
		Topic2:   "/qos0topic2",
	}
	clientOptions := mqtt.NewClientOptions().AddBroker(mqttConfig.Broker).SetUsername(mqttConfig.Username).SetPassword(mqttConfig.Password)
	client := mqtt.NewClient(clientOptions)

	var mqttHandler1 mqtt.MessageHandler = func(client mqtt.Client, msg mqtt.Message) {
		var data Temperature
		if err := json.Unmarshal(msg.Payload(), &data); err != nil {
			fmt.Println("Failed to parse MQTT message:", err)
			return
		}

		result := db.Create(&data)
		if result.Error != nil {
			fmt.Println("Failed to save data to database:", result.Error)
			return
		}

		fmt.Println("Temperature data saved successfully:", data)
	}

	var mqttHandler2 mqtt.MessageHandler = func(client mqtt.Client, msg mqtt.Message) {
		var data Location
		if err := json.Unmarshal(msg.Payload(), &data); err != nil {
			fmt.Println("Failed to parse MQTT message:", err)
			return
		}

		result := db.Create(&data)
		if result.Error != nil {
			fmt.Println("Failed to save data to database:", result.Error)
			return
		}

		fmt.Println("Location data saved successfully:", data)
	}

	if token := client.Connect(); token.Wait() && token.Error() != nil {
		panic("Failed to connect to MQTT broker: " + token.Error().Error())
	}

	if token := client.Subscribe(mqttConfig.Topic1, 0, mqttHandler1); token.Wait() && token.Error() != nil {
		panic("Failed to subscribe to MQTT topic 1: " + token.Error().Error())
	}

	if token := client.Subscribe(mqttConfig.Topic2, 0, mqttHandler2); token.Wait() && token.Error() != nil {
		panic("Failed to subscribe to MQTT topic 2: " + token.Error().Error())
	}

	r.Run(":8080")
}

func setMessageNotice(d *gorm.DB, c *gin.Context, data struct {
	DeviceID    string `json:"device_id"`
	Rate        int64  `json:"rate"`
	Difference  string `json:"difference"`
	Threshold   string `json:"threshold"`
	Phonenotice string `json:"phone_notice"`
	Msgnotice   string `json:"msg_notice"`
}) {

}

type TemperatureResult struct {
	ID          uint    `json:"id"`
	DeviceID    string  `json:"device_id"`
	Temperature string  `json:"temperature"`
	Lat         string  `json:"lat"`
	Lon         string  `json:"lon"`
	Electricity string  `json:"electricity"`
	Online      int     `json:"online"`
	Time        string  `json:"time"`
	MaxTemp     float64 `json:"max_temp"`
	MinTemp     float64 `json:"min_temp"`
}

type getLatestDataResult struct {
	DeviceID    string  `json:"device_id"`
	Temperature float64 `json:"temperature"`
	Lat         string  `json:"lat"`
	Lon         string  `json:"lon"`
	Online      int     `json:"online"`
	Time        string  `json:"time"`
	Electricity string  `json:"electricity"`
}

func getLatestData(c *gin.Context, db *gorm.DB) ([]getLatestDataResult, error) {

	var data []getLatestDataResult
	err := db.Raw(`
            SELECT t1.*
            FROM temperatures t1
            JOIN (
                SELECT device_id, MAX(time) AS max_time FROM temperatures GROUP BY device_id
            ) t2 ON t1.device_id = t2.device_id AND t1.time = t2.max_time
        `).Scan(&data).Error

	if err == gorm.ErrRecordNotFound {
		fmt.Println("数据库中没有数据")
		c.JSON(http.StatusOK, gin.H{"data": []struct{}{}})
		return nil, nil
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return nil, err
	}

	for i := range data {
		var location Location
		err := db.Where("device_id = ?", data[i].DeviceID).Last(&location).Error
		if err != nil {
			if err == gorm.ErrRecordNotFound {
				continue
			} else {
				log.Println(err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return nil, err
			}
		}
		var tem Temperature
		err = db.Where("device_id = ?", data[i].DeviceID).Last(&tem).Error
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return nil, err
		}
		data[i].Electricity = tem.Electricity
		data[i].Lat = location.Lat
		data[i].Lon = location.Lon
		locationTime, _ := strconv.ParseInt(location.Time, 10, 64)
		if time.Now().Unix()-locationTime > 300 {
			log.Print("time.Now().Unix()", time.Now().Unix())
			log.Println("location.Time:", location.Time)
			data[i].Online = 0
		} else {
			data[i].Online = 1
		}
	}

	return data, nil
}
func getTemperatureResult(db *gorm.DB, deviceID string, startTime int64, endTime int64) (*TemperatureResult, error) {
	var result TemperatureResult
	log.Println("deviceID:", deviceID, "startTime:", startTime, "endTime:", endTime)
	// 查询在线状态
	var location Location
	err := db.Where("device_id = ? AND time >= ? AND time <= ?", deviceID, startTime, endTime).Order("time DESC").First(&location).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			result.Online = 0
		} else {
			return nil, err
		}
	} else {
		locationTime, _ := strconv.ParseInt(location.Time, 10, 64)
		if time.Now().Unix()-locationTime > 300 {
			result.Online = 0
		} else {
			result.Online = 1
		}
	}

	// 查询当前温度
	var temperature Temperature
	err = db.Where("device_id = ?", deviceID).Order("time DESC").First(&temperature).Error
	if err != nil {
		return nil, err
	}
	result.Temperature = temperature.Temperature

	// 查询最高温度和最低温度
	type MaxMinTemp struct {
		MaxTemp float64 `json:"max_temp"`
		MinTemp float64 `json:"min_temp"`
	}
	var maxMin MaxMinTemp
	err = db.Raw("SELECT MAX(temperature) AS max_temp, MIN(temperature) AS min_temp FROM temperatures WHERE device_id = ? AND time >= ? AND time <= ?", deviceID, startTime, endTime).Scan(&maxMin).Error
	if err != nil {
		return nil, err
	}
	result.MaxTemp = maxMin.MaxTemp
	result.MinTemp = maxMin.MinTemp

	// 查询经纬度和剩余电量
	var loc Location
	err = db.Where("device_id = ?", deviceID).Order("time DESC").First(&loc).Error
	if err != nil {
		return nil, err
	}
	var tem Temperature
	err = db.Where("device_id = ?", deviceID).Order("time DESC").First(&tem).Error
	if err != nil {
		return nil, err
	}
	result.Lat = loc.Lat
	result.Lon = loc.Lon
	result.Electricity = tem.Electricity
	result.DeviceID = loc.DeviceID
	result.Electricity = tem.Electricity
	result.Time = loc.Time
	log.Println(&result)
	return &result, nil
}
func getTemperatureByDeviceID(db *gorm.DB, c *gin.Context, deviceID string, startTime int64, endTime int64) (*[]resultData, error) {
	var resultDatas []resultData
	err := db.Where("device_id = ? AND time >= ? AND time <= ?", deviceID, startTime, endTime).Table("temperatures").Find(&resultDatas).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return nil, err
	}
	log.Println(resultDatas)
	return &resultDatas, nil
}
