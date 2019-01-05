import boto3
import logging
import hashlib

logger = logging.getLogger(__name__)


class Zoo:
    def __init__(
        self,
        s3_name,
        db_name,
    ):
        """
        The zoo class for interacting with the zoo. Bucket and table must
        already exist
        Params:
        -s3_name - Name of s3 bucket to use
        -db_name - Name of dynamoDB table to use
        """
        self.bucket = boto3.resource('s3').Bucket(s3_name)
        self.table  = boto3.resource('dynamodb').Table(db_name)


    def add_sample(
        self,
        filestream,
        sourcetype = 'other',
        extra_attr = {}
    ):
        """
        Given a sample with a filestream-like object, calculate relevant
        hashes and add them. Sourcetype should specify where it originated
        from and source_attr can be used to pass additional values that are
        potentially relevant.
        """
        sample = dict()
        sample['sha256'] = hashlib.sha256(filestream.read()).hexdigest()

        if 'Item' in self.table.get_item(Key=sample):
            logger.info("Hash {} already in database. Not adding.".format(
                sample['sha256']
            ))
            return None
        
        filestream.seek(0)
        sample['sha1']   = hashlib.sha1  (filestream.read()).hexdigest()
        filestream.seek(0)
        sample['md5']    = hashlib.md5   (filestream.read()).hexdigest()
        filestream.seek(0)

        sample['sourcetype'] = sourcetype
        sample['extra_attr'] = extra_attr

        resp = self.table.put_item(Item=sample)
        logger.debug("Table put response: {}".format(resp))

        resp = self.bucket.upload_fileobj(filestream, sample['sha256'])
        logger.debug("Bucket put response: {}".format(resp))
