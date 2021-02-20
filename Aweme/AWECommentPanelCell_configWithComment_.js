// trace -[AWECommentPanelCell configWithComment:] method
if (ObjC.available && ("AWECommentPanelCell" in ObjC.classes)) {
    var AWECommentPanelCell = ObjC.classes.AWECommentPanelCell;

    var configWithComment_ = AWECommentPanelCell["- configWithComment:"];
    if (typeof configWithComment_ == 'undefined') {
        console.log('method -[AWECommentPanelCell configWithComment:] not found.');
    } else {
        Interceptor.attach(configWithComment_.implementation, {
            onEnter: function (args, state) {
                var model = new ObjC.Object(args[2]);
                var desc = model["- _ivarDescription"]();
                console.log(`-[AWECommentPanelCell configWithComment:${args[2]}]\n`, desc.toString());
            },
        });
    }
}

/*
输出结果如下：
================================================================================
[iPhone::抖音]-> -[AWECommentPanelCell configWithComment:0x12c1152c0]
 <AWECommentModel: 0x12c1152c0>:
in AWECommentModel:
	_likedByCreator (BOOL): NO
	_needShowChangeUserNameTips (BOOL): NO
	_userDigged (BOOL): NO
	_userBuried (BOOL): NO
        _isPin (BOOL): NO
	_isAdComment (BOOL): NO
	_isVideoTitle (BOOL): NO
	_disableAdTag (BOOL): NO
        _isSubComment (BOOL): NO
	_useV2API (BOOL): YES
	_isDuplicate (BOOL): NO
	_commentID (NSString*): @"6925560147083673614"
	_content (NSString*): @"有个小孩跳下水了"
	_awemeID (NSString*): @"6924587387871907084"
	_createTime (NSNumber*): @1612482634
	_diggCount (NSNumber*): @0
	_status (long): 1
	_author (AWEUserModel*): <AWEUserModel: 0x10db99e00>
	_authorInteractionLabelArray (NSArray*): nil
	_replyID (NSString*): @"0"
	_replySubCommentID (NSString*): @"0"
	_replySubCommentAutherName (NSString*): nil
	_tagType (long): -1
	_tagText (NSString*): @""
	_tagColor (NSString*): nil
	_tagTextColor (NSString*): nil
	_tagURL (NSString*): nil
	_replyComments (NSArray*): nil
	_textExtras (NSArray*): <__NSArray0: 0x1ea923538>
	_adLinkText (NSString*): nil
	_model (AWEAwemeModel*): <AWEAwemeModel: 0x10ef3c800>
	_relationLabel (AWERelationDynamicLable*): nil
	_repostId (NSString*): nil
	_subCommentCount (NSNumber*): @0
	_replyUserId (NSString*): nil
	_commentShowVV (NSString*): nil
	_sticker (AWEIMStickerModel*): nil
	_replyVideoModel (AWEAwemeModel*): nil
	_itemUserID (NSString*): @"2585690046993453"
	_commentH (double): 0
	_replyH (double): 0
	_replyStyle (long): 2
	_showCollapseCount (NSNumber*): nil
	_labelInfo (NSString*): nil
	_commentEasterEgg (AWECommentEasterEggModel*): nil
	_nameSize (struct CGSize): {0, 0}
	_replyNameSize (struct CGSize): {0, 0}
	_timeSize (struct CGSize): {0, 0}
in AWEBaseApiModel:
	_requestID (NSString*): @"2021022011280801015119620118008A89"
	_statusCode (NSNumber*): nil
	_timestamp (NSNumber*): nil
	_statusMsg (NSString*): nil
	_logPassback (NSDictionary*): <__NSSingleEntryDictionaryI: 0x281657d60>
in MTLModel:
in NSObject:
	isa (Class): AWECommentModel (isa, 0x61a10a2b6c7f)

================================================================================
*/