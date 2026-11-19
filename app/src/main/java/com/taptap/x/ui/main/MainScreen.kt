package com.taptap.x.ui.main

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.DrawerValue
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.NavigationDrawerItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.rememberDrawerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.taptap.x.R
import com.taptap.x.ui.theme.colorFabActive
import kotlinx.coroutines.launch

/**
 * Main screen, mirroring v2rayNG's MainScreen layout: ModalNavigationDrawer
 * + Scaffold (TopAppBar, server list, bottom status bar) + FAB connect.
 * The FAB is orange (#f97910) when the tunnel is active, grey otherwise
 * (same as v2rayNG's colorFabActive / colorFabInactive).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    viewModel: MainViewModel,
    onAddServer: () -> Unit,
    onEditServer: (String) -> Unit,
    onOpenSettings: () -> Unit,
    onOpenLog: () -> Unit,
    onToggleRunning: () -> Unit,
) {
    val profiles by viewModel.profiles.collectAsStateWithLifecycle()
    val selectedGuid by viewModel.selectedGuid.collectAsStateWithLifecycle()
    val isRunning by viewModel.isRunning.collectAsStateWithLifecycle()
    val statusText by viewModel.statusText.collectAsStateWithLifecycle()

    val drawerState = rememberDrawerState(DrawerValue.Closed)
    val scope = rememberCoroutineScope()

    ModalNavigationDrawer(
        drawerState = drawerState,
        drawerContent = {
            ModalDrawerSheet {
                Text(
                    text = stringResource(R.string.app_name),
                    style = MaterialTheme.typography.titleLarge,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 16.dp)
                )
                NavigationDrawerItem(
                    label = { Text(stringResource(R.string.menu_settings)) },
                    selected = false,
                    onClick = {
                        scope.launch { drawerState.close() }
                        onOpenSettings()
                    }
                )
                NavigationDrawerItem(
                    label = { Text(stringResource(R.string.menu_log)) },
                    selected = false,
                    onClick = {
                        scope.launch { drawerState.close() }
                        onOpenLog()
                    }
                )
                NavigationDrawerItem(
                    label = { Text(stringResource(R.string.menu_about)) },
                    selected = false,
                    onClick = { scope.launch { drawerState.close() } }
                )
            }
        }
    ) {
        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text(stringResource(R.string.app_name)) },
                    navigationIcon = {
                        IconButton(onClick = { scope.launch { drawerState.open() } }) {
                            Icon(
                                Icons.Filled.Menu,
                                contentDescription = stringResource(R.string.menu_open)
                            )
                        }
                    },
                    actions = {
                        IconButton(onClick = onAddServer) {
                            Icon(
                                Icons.Filled.Add,
                                contentDescription = stringResource(R.string.menu_add_server)
                            )
                        }
                    }
                )
            },
            bottomBar = {
                androidx.compose.material3.BottomAppBar(
                    containerColor = MaterialTheme.colorScheme.surfaceContainerLow
                ) {
                    Text(
                        text = statusText.ifBlank {
                            if (isRunning) stringResource(R.string.status_running)
                            else stringResource(R.string.status_stopped)
                        },
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier
                            .weight(1f)
                            .padding(horizontal = 16.dp)
                    )
                }
            },
            floatingActionButton = {
                FloatingActionButton(
                    onClick = onToggleRunning,
                    containerColor = if (isRunning) colorFabActive
                    else MaterialTheme.colorScheme.surfaceContainerHighest,
                    contentColor = if (isRunning) androidx.compose.ui.graphics.Color.White
                    else MaterialTheme.colorScheme.onSurface,
                ) {
                    Icon(
                        imageVector = if (isRunning) Icons.Filled.Stop else Icons.Filled.PlayArrow,
                        contentDescription = if (isRunning) stringResource(R.string.action_stop)
                        else stringResource(R.string.action_start)
                    )
                }
            }
        ) { innerPadding ->
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding)
            ) {
                if (profiles.isEmpty()) {
                    Text(
                        text = stringResource(R.string.empty_servers),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.align(Alignment.Center)
                    )
                } else {
                    LazyColumn(modifier = Modifier.fillMaxSize()) {
                        items(profiles, key = { it.guid }) { item ->
                            ServerRow(
                                item = item,
                                selected = item.guid == selectedGuid,
                                delayText = "",
                                onClick = { viewModel.select(item.guid) },
                                onLongClick = { onEditServer(item.guid) },
                            )
                        }
                    }
                }
            }
        }
    }
}
