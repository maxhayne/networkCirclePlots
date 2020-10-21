# networkCirclePlots

A new way to view traffic, building on and optimizing [<i>circlize</i>](https://jokergoo.github.io/circlize_book/book/).
<br/><br/>

<p align="center">
  <img src="/images/ntp_3std_1.jpg" width="800" />
</p>
<p align="center">
  Figure 1. Circle Plots in a Small Multiples Grid
</p>

### Introduction

From ([McAndrew et al., 2019, 51MB](http://selfsynchronize.com/hayne/papers/HICSS_2019_Comparison_of_Supervised_and_Unsupervised_Learning_for_Detecting_Anomalies_in_Network_Traffic.pdf)): given a set of SIPs (source IPs), a network visual representation should: (1) display functional/temporal characteristics of the flows, (2) demonstrate behavior of the SIP with respect to the network, and (3) demonstrate behavior of the SIP with respect to the individual DIPs (destination IPs) it contacts. They do not merely adapt an existing circle plot technique ([Krzywinski, M. et al.] (http://circos.ca/)), rather, they take the individual aspects and features of examples from their work and adapt them to construct a new representation specific to network traffic.

Each circle plot shown below represents a single SIP's activity (indicated by the title/label) over a fixed length of time, and consists of two components, called the “outer track” and the “inner ribbons”. The outer track consists of multiple segments (example shown on the left in Figure 2). The segment to the right of the vertical radial at the top of the circle corresponds to the SIP, and is always highlighted yellow. The remaining segments represent the unique DIPs contacted by that SIP. Inside each of these segments, we plot the time series of non-zero packet flows with the time increasing clockwise in each. The yellow-highlighted segment displays the series of packets sent by the SIP, while all other segments display the series of packets sent back to the SIP by the individual DIPs. The length of time represented in these segments is specified by the time-series of observations (i.e., seconds/minutes/hours/days) in the dataset. Note that each segment displays the same amount of time, and that this is not related to the size of the individual segments - the width of each is determined by how many segments must be drawn, and thus how many DIPs were contacted by the SIP. In cases where many DIPs are contacted (more than 99), the outer track can become densely packed with segments making each very narrow, and thus the individual segments may not be visible.

<p align="center">
  <img src="/images/CirclePlot_Basic1.png" width="300" />
  <img src="/images/CirclePlot_Basic2.png" width="300" />
</p>
<p align="center">
  Figure 2. Basic Circle Plot Layouts
</p>

Ribbons are drawn in the interior of the circle (example shown on the right in Figure 2) and connect the yellow SIP segment to the distinct DIP segments; representing an attempted connection. Ribbons originate in the SIP segment at the time the packets were sent, and terminate at the segment representing the DIP at the time they were received. A teal ribbon denotes that the DIP sent packets back to the SIP, while an amber ribbon denotes that it did not.	

A circle plot allows for visualization of a SIP's activity in a window of time, specifically the frequency and severity of contacts made. A large number of segments in the outer track corresponds to a large number of DIPs contacted. The plotted points within segments visualize the relative volume of packets sent and received by the SIP. The location and amount of ribbons show when and how often these contacts were made. The color of the ribbons gives an immediate notion of the proportion of successful contacts. To illustrate these benefits, consider the circle plot on the right side of Figure 2, where SIP X.X.X.X contacted 11 unique DIPs (11 non-highlighted segments around the circle), sporadically (some gaps between points in the yellow SIP segment) and with intermittent success (both teal and amber ribbons). The SIP sent relatively more packets in the beginning of the period than the end, as the purplish points in the SIP segment nearer to the vertical radial are closer to the outer edge than those at the other end of the SIP segment. When the DIPs replied (teal), they sent an “average” number of packets back, represented by the purplish points between the inner and outer edges.

<!-- Eventually Replace these images with higher-resolution generated attack data. -->
<p align="middle">
  <!--<img src="/images/CirclePlot_Grid1.png" width="400" /> -->
  <!--<img src="/images/CirclePlot_Grid2.png" width="400" /> -->
  <img src="/images/ntp_10std_1.jpg" width="800" />
</p>
<p align="center">
  Figure 3. Circle Plots in a Small Multiples Grid
</p>

Comparing behaviors between SIPs can be done by organizing circle plots in a grid of [small multiples](https://en.wikipedia.org/wiki/Small_multiple) (Tufte et al., 1990). As shown in Figure 3, we propose it is easy to get a gestalt of the types of outliers, which can give insight and build confidence in any subsequent analytics that might be performed. Figure 3's grid is only an example, but <i>networkCirclePlots</i> currently provides three options for within-grid sorting (IP, Cluster, and threatLevel).

### Problem Summary and Overview of Improvements

Visualization of network data with circle plots can be particularly useful when analyzing DDoS attacks post-hoc, under the assumption that the nodes which orchestrated the attack have been partially identified and tracked throughout the event. An analyst combing the raw data without the aid of visualization may be hard-pressed to find patterns or anomalous behavior in the time frame leading up to or during the event, while an analyst equipped with visual tools may not. However, visualization with <i>circlize</i> takes significant compute time, and as the number of points and links and sectors in a circle plot increases, so does its draw time. <i>circlize</i>, the R package that makes these types of visualizations possible, relies ultimately on base R for low-level calls to draw points, links, and sectors, and is thus limited by the speed at which R can plot. 

As an example, an outlier node (SIP) might be identified which has made contact with 3000 DIPs, and has exchanged an average of 100 packets with each. The information about these 100 packets may be encapsulated in 15-30 data rows, each of which corresponds to a point-link pair. Barring optimizations, a plot this complex requires a minimum of 138,000 calls to a generalized <i>draw</i> function (3000 sectors, <img src="https://render.githubusercontent.com/render/math?math=15 * 2 * 3000=90000"> points, and <img src="https://render.githubusercontent.com/render/math?math=15 * 3000=45000"> links). On a Dell PowerEdge R430 (Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz w/ 40 cores, 256GB RAM), which is the machine this code was developed and tested with, the draw time for Figure 4 is approximately 1400 seconds.

<p align="middle">
  <img src="/images/3000_dests_slow_1399.png" width="400" />
</p>
<p align="center">
  Figure 4. High Sector-Count Example
</p>

This presents a problem, not only because an analyst should not have to wait 23 minutes for a single plot to draw, but because if this technique were to be used in a real-time setting, where batches of new data are visualized every minute, plotting would not be able to keep up with the stream. And, it's important to note that this is only one plot. During a real DDoS attack, there may be any number of these types of SIPs (or other types of SIPs which call <i>draw</i> with similar magnitude), whose addition to a grid of plots linearly increases its draw time. 

#### Optimization

I suggest there are two approaches to increase plotting speed. The first approach is to parallelize calls to the <i>draw</i> function. One could imagine a data frame filled with network data, which could be iterated over using multiple cores in some sort of loop, and within each iteration of the loop <i>draw</i> is called for that particular value. Unfortunately, the programming language R, of which this software (and the software it depends on) is written, does not support parallelized plotting to the <i>same</i> canvas by multiple cores. Therefore, this approach is impossible, or at the least, not currently workable using base R. R does, however, allow multiple cores to each draw to their own plotting surface simultaneously. The second approach is to, as the plots become more complex, summarize the data before plotting it. The benefits of this approach are two-fold. Not only does it allow quicker generation of complex plots by single cores, it also allows for fine-tuning of visual features over the range of possible inputs. No visualization technique is perfect for every use case, and similar to how a force-directed graph may be cluttered and important information obfuscated in a bramble of links, circle plots with high sector-counts and numerous connections may be less informative than their simpler counterparts. For these reasons, summarizing, used in conjunction with multiple cores, are what <i>networkCirclePlots</i> aims to provide. 

By categorizing plots by the number of calls to <i>draw</i> they require, and labelling that metric the plot's <i>taskCount</i>, one can apply different graphing techniques within a single grid of outliers on a case-by-case basis. While testing draw times for plots with a wide array of <i>taskCounts</i>, it became apparent that 100 tasks took, on average, one second to draw. This was crucial, as it allowed for boundaries between plotting techniques to be adjusted to accomodate a worst-case-scenario under a time constraint. The largest number of outlier SIPs we have detected in a single batch is around 180, and the machine being used to draw the plots has 30 logical processors. Also, because batches from the <i>Netbrane</i> project are generated every minute, and outlier detection and clustering takes 10 seconds, 50 seconds are left for visualization. So, if there are 30 logical processors drawing a maximum of 180 plots in 50 seconds, each plot must require, on average, 7-8 seconds to draw (<img src="https://render.githubusercontent.com/render/math?math=50/(180/30)=8.333"> seconds). I've opted to set the <i>taskCount</i> at which default drawing behavior ends and summarized drawing begins at 700. This, in theory, sets the maximum draw-time for a single circle plot to 7 seconds. 

If a plot contains 700 or more tasks but fewer than 250 sectors, all links between the SIP and a given DIP are replaced with a single [chord](/images/chord-link.png) (wide link), color-coded such that if at any point during the correspondence between the SIP and that particular DIP, the DIP responded to a message from the SIP, the entire link is made teal. Otherwise, it is made amber. This was chosen deliberately, because as a SIP contacts more DIPs, it becomes meaningful to show the proportion of success with which it receives replies; if the SIP is an attacker, how informed is this attacker, and does it know the network well enough to illicit responses from vulnerable nodes? Additionally, inside all segments, individual points are replaced with horizontal lines, whose y-value represents the average PacketCount sent by that IP over the time frame. 

If a plot contains over 250 sectors, individual sectors are no longer drawn, as they become too thin discern. Instead, two sectors are drawn: the SIP's sector, and the DIPs sector (which represents all DIPs, and is proportional in size to their share of the total number of sectors). The DIPs sector is then shaded, from light grey (250 sectors) to black (5000 sectors). In so doing, an extra visual cue is added, giving the viewer a sense of the number of DIPs contacted by the SIP. Also, a line spanning the DIPs sector is drawn to show the average number of packets replied with by each DIP. And, because DIPs in all plots are arranged clockwise from smallest to largest average RPacketCount (the number of packets they reply to the SIP with), the line's y-value should only increase in the clockwise direction.

#### Parallelization

Regardless of the technique with with individual plots are drawn, multiple threads will be utilized when the <i>outliers</i> data frame contains more than one SIP. This is done with the help of the <i>doParallel</i> and <i>foreach</i> packages. The <i>foreach</i> package allows a user to register what is called a "parallel backend", in this case <i>doParallel</i>, which is responsible for scheduling and divvying up iterations within the foreach-loop to a specified number of cores with the fork() command. fork()'ing is not the only technique for allowing foreach-loop iterations to be individually run on different threads; another parallel backend called <i>doMPI</i> acts more like a thread pool by creating a cluster of cores which can be passed tasks as messages. But in numerous tests, this backend was less performant than <i>doParallel</i>. 

Once a thread has been assigned a plot, it creates a PNG file in the current session's "tmp" directory (which will be removed after the session has ended). This PNG is used as the plotting surface, and once the plotting has completed, a raster of the modified PNG is passed back to the main thread and arranged in a grid with the other plots' rasters. <i>foreach</i> offers 'multicore options' in its initialization, one of which is an option called 'preschedule', which pre-assigns looping iterations to specific cores. So, if <i>doParallel</i> uses four cores, and the foreach loop contains 16 plots, the first core will be assigned plots 1, 5, 9, and 13, while the fourth core will be assigned plots 4, 8, 12, and 16. This optimizes and streamlines the splitting of tasks to the cores, which in most scenarios is beneficial. But, if the plots are ordered randomly across iterations in the foreach-loop, a core could, simply by chance, be tasked with drawing the four most time-consuming plots in the grid. This stroke of misfortune would drastically increase the grid's creation time. Enabling the 'fast' option in either of the scripts mitigates this risk, as it lowers the variance in the range of possible draw times, and thus lowers the penalty for imperfect load balancing. As a result, 'prescheduling' is set to TRUE when the 'fast' option is enabled, but set to FALSE when the 'fast' option is disabled. Setting 'prescheduling' to FALSE means that tasks are assigned to cores on the fly, and the instant a core finishes drawing a plot, it is assigned to draw the next undrawn plot in foreach-loop iterating over the <i>outliers</i> data frame. 

In its current form, <i>networkCirclePlots</i> orders the plots in a data frame in the way that they'll be printed to the grid prior to drawing them. The foreach-loop then iterates over this data frame using the number of cores it has initialized. If we take the example mentioned earlier, with 16 plots and four cores, how should one sort these plots to maximize performance? Since some plots are more difficult to draw than others, it would make sense to draw the most time-consuming plots first, followed by the easier ones. Therefore, the data frame should be sorted in descending order based on <i>taskCount</i>. But, because <i>foreach</i> assigns P plots to C cores using the pattern where core c draws plots for which p % C evaluates to c, sorting only on <i>taskCount</i> isn't ideal. It would be more ideal to first sort on <i>taskCount</i>, then assign each element in the data frame a group number K, where K is equal to p % C. Then, where K is even (groups 2, 4...), reverse the order of plots within that grouping. This would make it so that in the previous example, the first core would be assigned plots 1, 8, 9, and 16, and the fourth core would be assigned plots 4, 5, 12, and 13. This approach lowers the average summed <i>taskCount</i> for every core across all of its plots. Intuitively, it pairs the hardest plot a core is assigned with an even easier plot, and does this for all other consecutive pairings, lowering the average load on that core.  

Overall, visual similarity has been prioritized throughout the optimization process, and any speedups unpreserving of the general look and feel of default plotting haven't been utilized. Below are examples of the different optimization tiers described above, paired with draw times. 


Type  | 3000 DIPs |  300 DIPs  | 100 DIPs  | 10 DIPs
:-------------------------:|:-------------------------:|:-------------------------:|:-------------------------: |:-------------------------:
Slow  |  ![](/images/3000_dests_slow_1399.png) 1399s |  ![](/images/300_dests_slow_50point818.jpg) 50.8s |  ![](/images/100_dests_slow_15point746.png) 15.7s |  ![](/images/10_dests_slow&fast_3point113.png) 3.1s
Fast  |  ![](/images/3000_dests_fast_3point387.png) 3.4s |  ![](/images/300_dests_fast_2point357.png) 2.4s |  ![](/images/100_dests_fast_3point931.png) 3.9s |  ![](/images/10_dests_slow&fast_3point113.png) 3.1s

<p align="center">
  Figure 5. Side-by-Side Comparison Of <i>Fast</i> and <i>Slow</i> Plots w/ Draw Times
</p>

Every column in Figure 5 uses its own set of input data. The input data was generated using the 'generateOneOutlier.py' script located in the 'test_data' folder, while modifying the 'count' variable on line 30. The three leftmost plots in the 'Fast' row of Figure 5 showcase the two optimization tiers described in the previous section. In the (Fast, 3000 DIPs) box, the SIP and the DIPs sectors are drawn, with the DIPs sector shaded to indicate the number of DIPs it holds. A line representing the average number of packets replied with by each DIP is drawn in the DIPs sector, and two chords, one amber and one teal, are drawn to their corresponding groups from the SIP sector to the DIPs sector. The (Fast, 300 DIPs) box uses the same technique as the (Fast, 3000 DIPs) box, but the DIPs sector is shaded more lightly to reflect the lower DIP count. In the (Fast, 100 DIPs) box, sectors for each DIP are drawn, but links between the SIP sector and every DIP sector are replaced with chords, and individual points are replaced with lines representing the average number of packets replied with by each DIP. In the '10 DIPs' column, the 'Fast' and 'Slow' rows plot the data unsummarized.

### Documentation

In the environment where this code is useful, the data from which these plots are created is stored in files and databases. It was therefore important for the main function to be callable from both the command-line and another R script. 

#### networkCirclePlots.R

<i>networkCirclePlots.R</i> is designed to be called from the command-line, using 'Rscript networkCirclePlots.R [Arguments]'. Issuing this command loads necessary libraries, parses arguments, and calls the function <i>makeCirclesFromFile(args)</i> to generate the plots. It takes a maximum of 14 arguments, but only one is required. It should be noted that this script should be used as an alternative way to call the function <i>makeCirclesFromeFile(args)</i>, and so all command-line arguments correspond to arguments that would be used in a call to that function. Arguments are parsed using the package <i>optparse</i>, so incorrect usage should result in an error along with an explanation. Inclusion of the '-h' flag will print a list of all possible arguments, and a description of how to use each:

	-o FILENAME, --outlier-file=FILENAME
		outliers file name (should include full path)

	-t FILE_EXT, --type=FILE_EXT
		file type of output {png,jpg,pdf} [default= jpg]

	-s STRING, --sort=STRING
		sort type of output {ip,cluster,threat} [default= ip]

	-a CHARACTER, --aspect-ratio=CHARACTER
		aspect ratio of output page {l=landscape,p=portrait} [default= l]

	-f, --fast
		enable plotting speedups [default= FALSE]

	-m STRING, --mask=STRING
		masking to be done to IPs {/0,/8,/16,/24,/32} [default= /0]

	-n STRING, --name=STRING
		name of the output file (includes path) and the title above the plots in the image (if no title is provided), file name defaults to the outlier's filename [default= NULL]

	-d, --dests
		destination sectors of circleplots will be labeled if <10 destinations [default= FALSE]

	-c INTEGER, --cores=INTEGER
		number of cores to use while drawing plots. default behavior uses detectCores()-2

	-b STRING, --banner=STRING
		the banner (title) of the page of plots. defaults to the name of the file

	-S STRING, --subnet=STRING
		the subnet of the network being monitored. defaults to null, but if null, checks for subnet in outlierFile name between '<time>_subnet_outliers.tsv'

	-M INTEGER, --max-data=INTEGER
		maximum packet count for a link or sector, above which a red dot or line will be drawn outside the sector [default= NULL]

	-D STRING, --data-column=STRING
		the data column in the 'links' file to use as the y-value in every sectors' plot {flow=FlowCount,byte=ByteCount,packet=PacketCount} [default= packet]

	-H DOUBLE, --h-ratio=DOUBLE
		a double between 0 and 1. closer to 0, the apex of a curved link drawn between two points passes nearer to the center of the circle plot [default= 0.7]

	-h, --help
		Show this help message and exit

If it is not called from the command-line, but instead loaded using <i>source("/path/networkCirclePlots.R")</i>, only the functions contained in the script will be loaded, and no attempt to read arguments will be made. The two functions, <i>makeCirclesFromFile(args)</i> and <i>makeCircles(args)</i> are very similar, but as can be inferred, <i>makeCirclesFromFile(args)</i> takes the name of an outlier file as an argument, while <i>makeCircles(args)</i> takes two data frames: the 'outliers' data frame and the 'links' data frame. And, because <i>makeCircles(args)</i> is not given an existing filename, it also requires the name of the output file from the user (which can include the filetype extension, but the parameter passed into the fileType argument will override). Otherwise, these two functions should behave the same way.

### Input Format

<i>makeCirclesFromFile(args)</i> expects an 'outliers' text file with a name in a specific format. The naming scheme is 'EPOCH-MINUTE_SUBNET_outliers.tsv'. The bisecting SUBNET is optional. But, to function correctly, there must be a corresponding <i>links</i> file in the same directory named 'EPOCH-MINUTE_SUBNET_links.tsv'. If a corresponding links file does not exist, the program exits. The <i>outliers</i> file must have this format (scroll right on shaded region if 7 columns aren't visible):
``` r
TEND	PROTOCOL	DPORT	SIP		PASS	clusterCenter	threatLevel
30	UDP		0	1.0.0.0		1	3		399
30	UDP		0	1.0.0.1		1	3		398
30	UDP		0	1.0.0.2		1	3		397
30	UDP		0	1.0.0.3		1	3		396
30	UDP		0	1.0.0.4		1	3		395
30	UDP		0	1.0.0.5		1	3		394
``` 
And the <i>links</i> file must have this format (scroll right on shaded region if 8 columns aren't visible): 
``` r
TEND	SIP		DIP		FlowCount	ByteCount	PacketCount	RByteCount	RPacketCount
0	100.200.300.1	100.200.0.0	0		0		1		0		0
2	100.200.300.1	100.200.0.0	0		0		1		0		0
3	100.200.300.1	100.200.0.0	0		0		1		0		0
6	100.200.300.1	100.200.0.0	0		0		1		0		0
8	100.200.300.1	100.200.0.0	0		0		1		0		0
9	100.200.300.1	100.200.0.0	0		0		1		0		0
```
