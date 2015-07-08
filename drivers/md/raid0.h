#ifndef _RAID0_H
#define _RAID0_H

struct strip_zone
{
	/*下一个区域的起始扇区*/
	sector_t zone_end;	/* Start of the next zone (in sectors) */
	/*在实际成员磁盘的区域偏移量*/
	sector_t dev_start;	/* Zone offset in real dev (in sectors) */
	/*当前区域的成员磁盘个数*/
	int nb_dev;		/* # of devices attached to the zone */
};

struct raid0_private_data
{
	struct strip_zone *strip_zone;
	mdk_rdev_t **devlist; /* lists of rdevs, pointed to by strip_zone->dev */
	int nr_strip_zones;
};

typedef struct raid0_private_data raid0_conf_t;

#endif
