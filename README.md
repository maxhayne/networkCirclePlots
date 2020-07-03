# networkCirclePlots
Software to speed up the process of drawing circle plots from network data.

# Introduction to the Network Circle Plot Visualization

Each circle plot shown below represents a single SIP's activity (indicated by the title/label) over a fixed length of time, and consists of two components, called the “outer track” and the “inner ribbons” ([Hayne et al., 2019](http://selfsynchronize.com/hayne/papers/Hayne_HICSS_2019_Comparison_of_Supervised_and_Unsupervised_Learning_for_Detecting_Anomalies_in_Network_Traffic.pdf)).  The outer track consists of multiple segments (an example shown on the left in Figure 1).  The segment to the right of the vertical radial at the top of the circle formed by this outer track is always highlighted yellow to indicate that it corresponds to the SIP.  The remaining segments represent unique DIPs contacted by that SIP.  Inside each of these segments, we plot the time series of non-zero packet flows with time increasing clockwise in each.  The yellow-highlighted segment displays the series of packets sent by the SIP, while all other segments display the series of packets sent back to the SIP by the individual DIPs.  The length of time represented in these segments is specified by the time-series of observations (i.e., seconds/minutes/hours/days) in the dataset.  Note that each segment displays the same amount of time, and that this is not related to the size of the individual segments - the annular width of each is determined by how many must be drawn, and thus how many DIPs were contacted by the SIP.  In cases where many DIPs are contacted (more than 99), the outer track can become densely packed with segments making each very narrow, and thus the individual segments may not be visible (for an example, see the circle plot on the right side of Figure ??).

<p align="center">
  <img src="/images/CirclePlot_Basic1.png" width="300" />
  <img src="/images/CirclePlot_Basic2.png" width="300" /> 
</p>

Ribbons are drawn in the interior of the circle (an example shown on the right in Figure 1) and connect the yellow SIP segment to the distinct DIP segments in order to represent an attempted connection.  Ribbons originate in the SIP segment at the time the packets were sent, and terminate at the segment representing the DIP at the time they were received.  A teal ribbon denotes that the DIP sent packets back to the SIP, while an amber ribbon denotes that it did not.	

A circle plot allows for visualization of a SIP's activity in a window of time, specifically the frequency and severity of contacts made.  Many segments in the outer track indicates a large number of DIPs contacted.  The points within segments visualize the relative volume of packets sent and received by the SIP.  The location and amount of ribbons show when and how often these contacts were made.  The color of the ribbons gives an immediate notion of the proportion of successful contacts.  To illustrate these benefits, consider the circle plot on the right side of Figure 1, where SIP X.X.X.X contacted 11 unique DIPs (11 non-highlighted segments around the circle), sporadically (some gaps between points in the yellow SIP segment) and with intermittent success (both teal and amber ribbons).  The SIP sent relatively more packets in the beginning of the period than the end, as points in the SIP segment closer to the vertical radial are closer to the outer edge than those at the other end of the SIP segment.  When the DIPs replied (teal), they sent an “average” amount of packets back.

<p align="middle">
  <img src="/images/CirclePlot_Grid1.png" width="400" />
  <img src="/images/CirclePlot_Grid2.png" width="400" /> 
</p>

Comparing behaviors between SIPs can be done by organizing circle plots in a grid of small multiples (Tufte et al., 1990).  As shown in Figure ??, we propose it is easy to get a gestalt of the types of outliers, which can give insight and build confidence in any subsequent clustering that might be performed.  The grids in Figure ?? are sorted by the number of DIP segments, but other sorting mechanisms could be used.



Single and Multi Core executions performed on Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz processors in a Dell PowerEdge R430 (40 cores, 256GB RAM).
