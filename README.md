# networkCirclePlots
Software to speed up the drawing circle plots from network data.

### Introduction to the Network Circle Plot Visualization

From ([McAndrew et al., 2019, 51MB](http://selfsynchronize.com/hayne/papers/HICSS_2019_Comparison_of_Supervised_and_Unsupervised_Learning_for_Detecting_Anomalies_in_Network_Traffic.pdf)): given a set of SIPs (source IPs), a network visual representation should: (1) display functional/temporal characteristics of the flows, (2) demonstrate behavior of the SIP with respect to the network and each other, and (3) demonstrate behavior of the SIP with respect to the individual DIPs (destination IPs) it contacts. We do not merely adapt an existing circle plot technique ([Krzywinski, M. et al.] (http://circos.ca/)), rather, we take the individual aspects and features of examples discussed in the literature and adapt them to construct a new representation specific to network traffic.

Each circle plot shown below represents a single SIP's activity (indicated by the title/label) over a fixed length of time, and consists of two components, called the “outer track” and the “inner ribbons”. The outer track consists of multiple segments (an example shown on the left in Figure 1). The segment to the right of the vertical radial at the top of the circle formed by this outer track is always highlighted yellow to indicate that it corresponds to the SIP. The remaining segments represent unique DIPs contacted by that SIP. Inside each of these segments, we plot the time series of non-zero packet flows with time increasing clockwise in each. The yellow-highlighted segment displays the series of packets sent by the SIP, while all other segments display the series of packets sent back to the SIP by the individual DIPs. The length of time represented in these segments is specified by the time-series of observations (i.e., seconds/minutes/hours/days) in the dataset. Note that each segment displays the same amount of time, and that this is not related to the size of the individual segments - the annular width of each is determined by how many must be drawn, and thus how many DIPs were contacted by the SIP. In cases where many DIPs are contacted (more than 99), the outer track can become densely packed with segments making each very narrow, and thus the individual segments may not be visible.

<p align="center">
  <img src="/images/CirclePlot_Basic1.png" width="300" />
  <img src="/images/CirclePlot_Basic2.png" width="300" />
</p>
<p align="center">
  Figure 1. Basic Circle Plot Layouts
</p>

Ribbons are drawn in the interior of the circle (an example shown on the right in Figure 1) and connect the yellow SIP segment to the distinct DIP segments in order to represent an attempted connection. Ribbons originate in the SIP segment at the time the packets were sent, and terminate at the segment representing the DIP at the time they were received. A teal ribbon denotes that the DIP sent packets back to the SIP, while an amber ribbon denotes that it did not.	

A circle plot allows for visualization of a SIP's activity in a window of time, specifically the frequency and severity of contacts made. A large number of segments in the outer track corresponds to a large number of DIPs contacted. The plotted points within segments visualize the relative volume of packets sent and received by the SIP. The location and amount of ribbons show when and how often these contacts were made. The color of the ribbons gives an immediate notion of the proportion of successful contacts. To illustrate these benefits, consider the circle plot on the right side of Figure 1, where SIP X.X.X.X contacted 11 unique DIPs (11 non-highlighted segments around the circle), sporadically (some gaps between points in the yellow SIP segment) and with intermittent success (both teal and amber ribbons). The SIP sent relatively more packets in the beginning of the period than the end, as points in the SIP segment closer to the vertical radial are closer to the outer edge than those at the other end of the SIP segment. When the DIPs replied (teal), they sent an “average” number of packets back.

<!-- Eventually Replace these images with higher-resolution generated attack data. -->
<p align="middle">
  <!--<img src="/images/CirclePlot_Grid1.png" width="400" /> -->
  <!--<img src="/images/CirclePlot_Grid2.png" width="400" /> -->
  <img src="/images/25_1_outliers.png" width="800" />
</p>
<p align="center">
  Figure 2. Grid-Style Circle Plots
</p>

Comparing behaviors between SIPs can be done by organizing circle plots in a grid of small multiples (Tufte et al., 1990). As shown in Figure 2, we propose it is easy to get a gestalt of the types of outliers, which can give insight and build confidence in any subsequent clustering that might be performed. The grids in Figure 2 are sorted by the number of DIP segments, but other sorting mechanisms can be used.

### Problem Summary and Overview of Improvements

Visualization of network data with circle plots can be particularly useful when analyzing DDos attacks post-hoc, under the assumption that the nodes which orchestrated the attack have been partially identified and tracked throughout the event. An analyst combing the raw data without the aid of visualization may be hard-pressed to find patterns or anomalous behavior in the time frame leading up to or during the event, while an analyst equipped with visual tools may not. However, visualization takes time, and as the number of points and links and sectors in a circle plot increases, so does its draw time. As an example, an outlier node (SIP) might be identified which has made contact with 3000 DIPs, and has exchanged an average of 100 packets with each. The information about these 100 packets may be encapsulated in 15-30 data rows, each of which corresponds to a point-link pair. Barring optimizations, a plot this complex requires a minimum of 138,000 calls to a generalized <i>draw</i> function (3000 sectors, <img src="https://render.githubusercontent.com/render/math?math=15 * 2 * 3000=90000"> points, and <img src="https://render.githubusercontent.com/render/math?math=15 * 3000=45000"> links). On a Dell PowerEdge R430 (Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz w/ 40 cores, 256GB RAM), which is the machine this code was developed and tested with, the draw time for this plot:

<p align="middle">
  <img src="/images/3000_dests_slow_1399.png" width="400" />
</p>
<p align="center">
  Figure 3. High Sector-Count Example
</p>

is approximately 1400 seconds. This presents a problem, not only because an analyst should not have to wait 23 minutes for a single plot to draw, but because if this technique were to be used in a real-time setting, where batches of new data are visualized every minute, plotting would not be able to keep up with the stream. And, it's important to note that this is only one plot. During a real attack, there may be any number of these types of SIPs (or other types of SIPs which call <i>draw</i> with similar magnitude), whose addition to a grid of plots linearly increases its draw time. From here there are two approaches to increase plotting speed. The first approach is to parallelize calls to the <i>draw</i> function. One could imagine a data frame filled with network data, which could be iterated over using multiple cores in some sort of loop, and within each iteration of the loop <i>draw</i> is called for that particular value. Unfortunately, the programming language R, of which this software (and the software it depends on) is written, does not support parallelized plotting to the <i>same</i> canvas by multiple cores. Therefore, this approach is impossible, or at the least, not currently workable using base R. The second approach is to, as the plots become more complex, summarize the data before plotting it. The benefits of this approach are two-fold. Not only does it allow quicker generation of complex plots by single cores, it also allows for a finer-tuning of visual features over the range of possible inputs. No visualization technique is perfect for every use-case, and similar to how a force-directed graph may be cluttered and important information obfuscated in a bramble of links, circle plots with high sector-counts and numerous connections may be less informative than their simpler counterparts. For these reasons, summarizing optimizations, used in conjunction with multi-core support (each circle plot in a grid is assigned to its own logical processor), are what <i>networkCirclePlots</i> aims to provide. 

By categorizing plots by the number of calls to <i>draw</i> they require, and labelling that metric the plot's <i>taskCount</i>, one can apply different graphing techniques within a single grid of outliers on a case-by-case basis. While testing draw times for plots with a wide array of <i>taskCounts</i>, it became apparent that 100 tasks took, on average, a second to draw. This was crucial, as it allowed for boundaries between graphing techniques to be adjusted to accomodate a worst-case-scenario under a time constraint. The largest number of outlier SIPs we have detected in a single batch is around 180, and the machine being used to draw the plots has 30 logical processors. Also, because batches are generated every minute, and data pre-processing and clustering takes 10 seconds, 50 seconds are left for visualization. So, if there are 30 logical processors drawing a maximum of 180 plots in 50 seconds, each plot must require, on average, 7-8 seconds to draw (<img src="https://render.githubusercontent.com/render/math?math=50/(180/30)=8.333"> seconds). I've opted to set the <i>taskCount</i> at which default drawing behavior ends, and summarized drawing begins at 700. This, in theory, sets the maximum draw-time for a single plot to 7 seconds. 

If a plot contains 700 or more tasks but fewer than 250 sectors, there will be at most one chord (wide link) drawn between the SIP and each DIP, color-coded such that if at any point during the correspondence between the SIP and that particular DIP, the DIP responded to a message from the SIP, the entire link is made teal. Otherwise, it is made amber. This was chosed deliberately, because as a SIP contacts more DIPs, it becomes meaningful to show the proportion of success with which it receives replies. In addition, regular points are replaced with horizontal lines whose y-value represents the average PacketCount sent by that IP over the time frame. 

If a plot contains over 250 sectors, individual sectors are no longer drawn, as they become too thin discern. Instead, two sectors are drawn: the SIP's sector, and the DIPs sector (which represents all DIPs, and is proportional in size to their share of the total number of sectors). The DIPs sector is then shaded, from light grey (250 sectors) to black (5000 sectors). In so doing, an extra visual cue is added, giving the viewer a sense of the number of DIPs contacted by the SIP. Also, a line spanning the DIPs sector is drawn to show the average number of packets sent by each DIP. And, because DIPs in all plots are arranged clockwise from smallest to largest by average RPacketCount, the line's y-value should only increase in the clockwise direction. 

Overall, qualitative similarity has been prized throughout the optimization process, and any speedups unpreserving of the general look and feel of default plotting haven't been utilized. Below are a few examples of the different optimization tiers described above, along with a table of draw times. 


Type  | 3000 DIPs |  300 DIPs  | 100 DIPs  | 10 DIPs
:-------------------------:|:-------------------------:|:-------------------------:|:-------------------------: |:-------------------------:
Slow  |  ![](/images/3000_dests_slow_1399.png)  |  ![](/images/300_dests_slow_50point818.png)  |  ![](/images/100_dests_slow_15point746.png)  |  ![](/images/10_dests_slow&fast_3point113.png)  
Fast  |  ![](/images/3000_dests_fast_3point387.png)  |  ![](/images/300_dests_fast_2point357.png)  |  ![](/images/100_dests_fast_3point931.png)  |  ![](/images/10_dests_slow&fast_3point113.png)

Type  | 3000 DIPs |  300 DIPs  | 100 DIPs  | 10 DIPs
:-------------------------:|:-------------------------:|:-------------------------:|:-------------------------: |:-------------------------:
Slow  |  1399s  |  50.8s  |  15.7s  |  3.1s  
Fast  |  3.4s  |  2.4s  |  3.9s  |  3.1s

<p align="center">
  Figure 4. Side-by-Side Comparison Of <i>Fast</i> and <i>Slow</i> Plots w/ Draw Times
</p>

