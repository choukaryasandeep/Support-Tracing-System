package services

import (
	"context"
	"time"

	"github.com/choukaryasandeep/support-ticket-system/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type CommentService struct {
	collection *mongo.Collection
}

func NewCommentService(collection *mongo.Collection) *CommentService {
	return &CommentService{collection: collection}
}

// AddComment adds a new comment to a ticket
func (cs *CommentService) AddComment(ticketID string, comment *models.Comment) error {
	ticketObjID, err := primitive.ObjectIDFromHex(ticketID)
	if err != nil {
		return err
	}

	comment.ID = primitive.NewObjectID()
	comment.CreatedAt = time.Now()

	// First, ensure the comments array exists
	_, err = cs.collection.UpdateOne(
		context.Background(),
		bson.M{"_id": ticketObjID},
		bson.M{"$setOnInsert": bson.M{"comments": []models.Comment{}}},
	)
	if err != nil {
		return err
	}

	// Then add the comment
	_, err = cs.collection.UpdateOne(
		context.Background(),
		bson.M{"_id": ticketObjID},
		bson.M{"$push": bson.M{"comments": comment}},
	)
	return err
}

// GetComments retrieves all comments for a ticket
func (cs *CommentService) GetComments(ticketID string) ([]models.Comment, error) {
	ticketObjID, err := primitive.ObjectIDFromHex(ticketID)
	if err != nil {
		return nil, err
	}

	var ticket models.Ticket
	err = cs.collection.FindOne(context.Background(), bson.M{"_id": ticketObjID}).Decode(&ticket)
	if err != nil {
		return nil, err
	}

	return ticket.Comments, nil
}
