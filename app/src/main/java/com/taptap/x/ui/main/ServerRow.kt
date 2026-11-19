package com.taptap.x.ui.main

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.taptap.x.data.ProfileItem
import com.taptap.x.ui.theme.colorConfigType
import com.taptap.x.ui.theme.colorPing

/**
 * One server row, mirroring v2rayNG's MainScreen row: remarks on the
 * first line (bold when selected), protocol label in orange, address
 * below, ping/delay on the right. Selected row gets the accent bar
 * on its left edge (handled by the caller via background).
 */
@Composable
fun ServerRow(
    item: ProfileItem,
    selected: Boolean,
    delayText: String,
    onClick: () -> Unit,
    onLongClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp)
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Row {
                Text(
                    text = item.displayName(),
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = item.typeLabel(),
                    style = MaterialTheme.typography.bodySmall,
                    color = colorConfigType,
                )
            }
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = "${item.address}:${item.port}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (delayText.isNotBlank()) {
            Text(
                text = delayText,
                style = MaterialTheme.typography.bodySmall,
                color = colorPing,
            )
        }
    }
}
