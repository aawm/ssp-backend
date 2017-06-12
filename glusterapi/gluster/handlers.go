package gluster

import (
	"net/http"
	"github.com/oscp/openshift-selfservice/glusterapi/models"
	"github.com/gin-gonic/gin"
	"log"
)

const (
	wrongApiUsageError = "Wrong API usage. Your payload did not match the endpoint"
)

func CreateVolumeHandler(c *gin.Context) {
	var json models.CreateVolumeCommand
	if c.BindJSON(&json) == nil {

		log.Printf("Got new request for a volume. project: %v size: %v", json.Project, json.Size)

		if err := createVolume(json.Project, json.Size); err != nil {
			log.Print("Volume creation failed", err.Error())

			c.JSON(http.StatusInternalServerError, gin.H{
				"message": err.Error(),
			})
		} else {
			log.Print("Volume was created")

			c.JSON(http.StatusOK, gin.H{
				"message": "Volume created",
			})
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"message": wrongApiUsageError})
	}
}

func CreateLVHandler(c *gin.Context) {
	var json models.CreateLVCommand
	if c.BindJSON(&json) == nil {

		log.Printf("Got new request for a lv. lvName: %v size: %v mountPoint: %v", json.LvName, json.Size, json.MountPoint)

		if err := createLvOnPool(json.Size, json.MountPoint, json.LvName); err != nil {
			log.Print("LV creation failed", err.Error())

			c.JSON(http.StatusInternalServerError, gin.H{
				"message": err.Error(),
			})
		} else {
			log.Print("LV was created")

			c.JSON(http.StatusOK, gin.H{
				"message": "LV created",
			})
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"message": wrongApiUsageError})
	}
}