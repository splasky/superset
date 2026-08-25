/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import { t } from '@apache-superset/core/translation';
import {
  getBootstrapDataFromDocument,
  getMapRendererOptions,
  OSM_TILE_STYLE_URL,
  type MapRendererOption,
  type MapProvider,
} from '@superset-ui/core/utils/mapStyles';
import { hasMapboxApiKey } from './mapbox';

export const POINT_CLUSTER_MAPLIBRE_STYLE_CHOICES = [
  ['https://tiles.openfreemap.org/styles/liberty', t('Liberty (OpenFreeMap)')],
  [
    'https://basemaps.cartocdn.com/gl/positron-gl-style/style.json',
    t('Light (Carto)'),
  ],
  [
    'https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json',
    t('Dark (Carto)'),
  ],
  [
    'https://basemaps.cartocdn.com/gl/voyager-gl-style/style.json',
    t('Streets (Carto)'),
  ],
  [OSM_TILE_STYLE_URL, t('Streets (OSM)')],
];

type PointClusterTileChoice = [string, string];

const isPointClusterTileChoices = (
  value: unknown,
): value is PointClusterTileChoice[] =>
  Array.isArray(value) &&
  value.length > 0 &&
  value.every(
    choice =>
      Array.isArray(choice) &&
      choice.length === 2 &&
      typeof choice[0] === 'string' &&
      choice[0].trim().length > 0 &&
      typeof choice[1] === 'string' &&
      choice[1].trim().length > 0,
  );

export function getPointClusterMapLibreStyleProps() {
  const bootstrapData = getBootstrapDataFromDocument();
  const deckglTilesOverride = (
    bootstrapData as {
      common?: { deckgl_tiles?: unknown };
    } | null
  )?.common?.deckgl_tiles;
  const choices = isPointClusterTileChoices(deckglTilesOverride)
    ? deckglTilesOverride
    : POINT_CLUSTER_MAPLIBRE_STYLE_CHOICES;

  return {
    choices,
    default: choices[0][0],
  };
}

export function getPointClusterMapRendererProps(currentValue?: MapProvider) {
  const hasKey = hasMapboxApiKey();
  return {
    options: getMapRendererOptions({
      hasMapboxKey: hasKey,
      currentValue,
    }).map((option: MapRendererOption) => ({
      ...option,
      label:
        option.value === 'maplibre'
          ? t('MapLibre (open-source)')
          : t('Mapbox (API key required)'),
    })),
  };
}
